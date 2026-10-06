## Mã nguồn

- Khai báo thư viện:

```python
import os
import sys
import time
import numpy as np
from collections import defaultdict

try:
    import dpkt
except ImportError:
    sys.exit(" ")
```

- Hàm lấy nhãn:

```python
def extract_label(filename):

    #lấy tên file
    name = os.path.basename(filename).lower()

    #so lấy nhãn
    if 'video' in name:
        return 'video'
    if any(k in name for k in ['audio', 'voipbuster', 'voip']):
        return 'voip'
    if any(k in name for k in ['ftps', 'sftp', 'scp', 'file']):
        return 'file'
    if any(k in name for k in ['youtube', 'vimeo', 'netflix', 'spotify']):
        return 'streaming'
    if any(k in name for k in ['chat', 'icq', 'aim']):
        return 'chat'
    if 'email' in name or 'mail' in name:
        return 'email'
    return None
```

- Đọc file pcap và trích những thông tin cần thiết từng packet (chỉ đọc được file NonVPN):

```python
def parse_pcap(stream, filename, max_packets=50000):

    #danh sách chứa các packet hợp lệ
    packets = []
    try:
        #Chọn loại reader
        Reader = dpkt.pcapng.Reader if filename.endswith('.pcapng') else dpkt.pcap.Reader

        #tạo obj đọc pcap
        reader = Reader(stream)
        
        #đọc từng packet: ts = timestamp, buf = dữ liệu raw của packet
        for ts, buf in reader:

            #giới hạn số packet
            if len(packets) >= max_packets:
                break
            try:

                #Giải mã chuỗi dữ liệu thô thành 1 ethernet frame để xử lý
                eth = dpkt.ethernet.Ethernet(buf)
                #kiểm tra packet có phải IPv4
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                
                ip = eth.data
                #Lấy packet có transport protocol là TCP hoặc UDP - Mục đích loại bỏ nhiễu do các gói tin không phải do người dùng tạo ra
                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    packets.append((
                        float(ts), #timestamp
                        dpkt.utils.inet_to_str(ip.src), ip.data.sport,  #source IP + port
                        dpkt.utils.inet_to_str(ip.dst), ip.data.dport,  #destination IP + port
                        ip.p, len(buf) #protocol + packet length
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return packets #Trả về danh sách dữ liệu mỗi packet
```

- Xử lý dữ liệu đầu vào cho mạng:

```python
def load_flows(pcap_dir, max_packets_per_file=30000,
               min_pkts=10, max_pkts_per_flow=200, max_flows_per_label=150):

    #Lấy tất cá file pcap trong bộ dữ liệu
    pcap_files = sorted(
        f for f in os.listdir(pcap_dir)
        if f.endswith(('.pcap', '.pcapng'))
    )

    #flow + nhãn của nó 
    all_flows, all_labels = [], []

    #đếm số flow
    label_counts = defaultdict(int)

    print(f"\nThư mục: {pcap_dir}")
    print(f"   Tìm thấy {len(pcap_files)} file PCAP/PCAPNG\n")

    #duyệt qua các file
    for fi, pname in enumerate(pcap_files, 1):
        
        #lấy nhãn
        label = extract_label(pname)
        if label is None:
            continue
        #giới hạn flow mỗi nhãn (dùng để test nên giới hạn)
        if max_flows_per_label is not None and label_counts[label] >= max_flows_per_label:
            continue
        
        filepath = os.path.join(pcap_dir, pname)
        print(f"  [{fi}/{len(pcap_files)}] {pname} [{label}]", end="")


        try:
            #mở file pcap và lấy dữ liệu
            with open(filepath, 'rb') as f:
                raw = parse_pcap(f, pname, max_packets_per_file)
        except Exception as e:
            print(f"{e}")
            continue

        if not raw:
            print(" (trống)")
            continue
        
        #Gom các packet thành flow
        fdict = defaultdict(list)
        for ts, sip, sp, dip, dp, proto, length in raw: 
            """
                ts = timestamp
                sip   = source IP
                sp    = source port
                dip   = destination IP
                dp    = destination port
                proto = protocol
                length = packet length
            """
            """
            Xếp lại để tạo ra cùng 1 key (nên có thêm 1 khoảng thời gian chờ 2 gói tin ở 1 mức limit nào đó vì có thể
            có 1 luồng sau 1 khoảng thời gian nào đó trùng các thông số, do bộ dữ liệu đang dùng không
            có vấn đề này + với mục đích bắt từng gói mỗi luồng nên hiện tại không thêm)
            """
            if (sip, sp) < (dip, dp):
                key = (sip, sp, dip, dp, proto)
            else:
                key = (dip, dp, sip, sp, proto)
            fdict[key].append((ts, length, sip)) #(timestamp, packet_length, source_ip)

        count = 0
        for key, pkts in fdict.items():
            #bỏ flow quá nhỏ
            if len(pkts) < min_pkts:
                continue
            #giói hạn số flow 1 label
            if max_flows_per_label is not None and label_counts[label] >= max_flows_per_label:
                break
            
            #sắp xếp theo timestamp
            pkts.sort()
            pkts = pkts[:max_pkts_per_flow] #giói hạn số gói tin mỗi luồng( chỉ phục vụ test - có những bài chỉ dùng 15 gói)

            #ip gửi packet đầu được coi là initiator
            true_initiator = pkts[0][2]

            #danh sách chứa dữ liệu
            feats = []
            #duyệt qua các packet trong 1 luồng: i - thứ tự từ 0 + các tham số timestamp, length, source ip
            for i, (ts, length, sip) in enumerate(pkts):

                #khoảng thời gian 2 gói tin
                dt = 0.0 if i == 0 else (ts - pkts[i - 1][0]) * 1000.0
                #lấy hướng truyền
                is_init = 1.0 if sip == true_initiator else 0.0
                #gộp 3 tham số lại và cho vào danh sách
                feats.append([dt, float(length), is_init])

            all_flows.append(np.array(feats, dtype=np.float32)) #nạp dữ liệu
            all_labels.append(label)
            label_counts[label] += 1
            count += 1

        print(f" → {count} flows")

    print(f"\n{'=' * 50}")
    print(f"Phân bố nhãn: {dict(label_counts)}")
    print(f"   Tổng: {len(all_flows)} flows")
    return all_flows, all_labels #Trả về flow + nhãn
```

- Mạng ReservoirSNN:
```python
class ReservoirSNN:
    def __init__(self, n_neurons=128, n_inputs=14, sparsity=0.12,
                 v_th=4.0, n_dt_bins=64, dt_range=(0.01, 10000.0), seed=42,
                 res_shift=2):
            """
                n_neurons:	số neuron Reservoir
                n_inputs:	số input feature sau encoding
                sparsity:	độ thưa của W_res
                v_th:	ngưỡng firing
                n_dt_bins:	số bin Δt
                dt_range:	khoảng Δt
                seed:	random seed
                res_shift:	mức giảm recurrent weight
            """
        self.N = n_neurons
        self.v_th = v_th    
        self.seed = seed
        self.res_shift = res_shift

        rng = np.random.RandomState(seed)

        mask = rng.random((n_neurons, n_neurons)) < sparsity
        signs = rng.choice([-1, 1], size=(n_neurons, n_neurons))
        np.fill_diagonal(mask, False)
        W = (mask * signs).astype(np.int8)

        self.W_res = W

        eigvals = np.linalg.eigvals(W)
        self.actual_rho = float(np.max(np.abs(eigvals)))
        self.rho_effective = self.actual_rho / (2 ** res_shift)

        in_mask = rng.random((n_neurons, n_inputs)) < 0.3
        in_signs = rng.choice([-1, 1], size=(n_neurons, n_inputs))
        self.W_in = (in_mask * in_signs).astype(np.int8)

        self.bin_edges = np.logspace(
            np.log10(dt_range[0]), np.log10(dt_range[1]), n_dt_bins + 1
        )
        bin_centers = np.sqrt(self.bin_edges[:-1] * self.bin_edges[1:])

        taus = [10.0, 50.0, 200.0, 1000.0]
        self.decays = np.zeros((n_neurons, n_dt_bins))
        group_size = n_neurons // len(taus)
        for g, t in enumerate(taus):
            start = g * group_size
            end = (g + 1) * group_size if g < len(taus) - 1 else n_neurons
            self.decays[start:end, :] = np.exp(-bin_centers / t)
            
        self.n_bins = n_dt_bins

        self.V = np.zeros(n_neurons)
        self.spikes = np.zeros(n_neurons)

    def reset(self):
        self.V[:] = 0.0
        self.spikes[:] = 0.0

    def process_flow(self, flow_features):
        n_steps = len(flow_features)
        V = np.zeros(self.N)
        spikes = np.zeros(self.N)

        dt_all = flow_features[:, 0].astype(np.float64)
        length_all = flow_features[:, 1].astype(np.float64)
        dir_all = flow_features[:, 2].astype(np.float64)

        X = np.zeros((n_steps, 14), dtype=np.float64)
        
        X[:, 0] = (length_all >= 70)
        X[:, 1] = (length_all >= 100)
        X[:, 2] = (length_all >= 200)
        X[:, 3] = (length_all >= 600)
        X[:, 4] = (length_all >= 1200)
        X[:, 5] = (length_all >= 1450)

        X[:, 6] = (dt_all >= 0.1)
        X[:, 7] = (dt_all >= 1)
        X[:, 8] = (dt_all >= 10)
        X[:, 9] = (dt_all >= 100)
        X[:, 10] = (dt_all >= 1000)
        X[:, 11] = (dt_all >= 10000)

        X[:, 12] = (dir_all == 1)
        X[:, 13] = (dir_all == 0)

        WinX = X @ self.W_in.T 

        decay_indices = np.searchsorted(self.bin_edges[1:], np.maximum(dt_all, 1e-6))
        decay_indices = np.clip(decay_indices, 0, self.n_bins - 1)

        scale = 2 ** self.res_shift
        spike_counts = np.zeros(self.N, dtype=np.float64)
        states_over_time = np.zeros((n_steps, self.N))

        for i in range(n_steps):
            if i > 0:
                V *= self.decays[:, decay_indices[i]]

            recurrent = self.W_res @ spikes
            V += WinX[i] + recurrent / scale

            fired = V > self.v_th
            spikes = fired.astype(np.float64)
            V[fired] -= self.v_th
            
            spike_counts += spikes
            states_over_time[i] = spike_counts.copy()

        return states_over_time

from sklearn.linear_model import RidgeClassifier
from sklearn.model_selection import cross_val_score
```