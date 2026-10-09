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
                #Lấy packet có transport protocol là TCP hoặc UDP
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
    return all_flows, all_labels #Trả về flow voi 3 features + nhãn
```

- Mạng ReservoirSNN:
```python
class ReservoirSNN:
    def __init__(self, n_neurons=128, n_inputs=14, sparsity=0.12,
                 v_th=4.0, n_dt_bins=64, dt_range=(0.01, 10000.0), seed=36,
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

        #Bộ random số ngẫu nhiên
        rng = np.random.RandomState(seed)

        #Tạo ma trận W_res
        mask = rng.random((n_neurons, n_neurons)) < sparsity #ma trận n*n , 13% xác suất kết nối
        signs = rng.choice([-1, 1], size=(n_neurons, n_neurons)) #Ma trận n*n, giá trị -1, 1
        np.fill_diagonal(mask, False) #xóa kết nối trên đường chéo
        W = (mask * signs).astype(np.int8) # Ma trận trọng số chỉ có 3 giá trị -1, 0, 1

        self.W_res = W

        eigvals = np.linalg.eigvals(W) # tính các trị riêng W_res
        self.actual_rho = float(np.max(np.abs(eigvals)))# tìm giá trị tuyệt đối lớn nhất
        self.rho_effective = self.actual_rho / (2 ** res_shift)# Spectrial radius hiệu dụng (dịch res_shift bits)

        #Tạo ma trận W_in N*n_inputs
        in_mask = rng.random((n_neurons, n_inputs)) < 0.3
        in_signs = rng.choice([-1, 1], size=(n_neurons, n_inputs))
        self.W_in = (in_mask * in_signs).astype(np.int8)

        #Tạo LUT
        self.bin_edges = np.logspace(
            np.log10(dt_range[0]), np.log10(dt_range[1]), n_dt_bins + 1
        ) #lấy log điểm đầu + điểm cuối sau đó chia đều n_dt_bins khoảng cho n_dt_bins + 1 phần tử -> tạo mảng n_dt_bins + 1  phần từ x với x = 10**i for i in range[mảng chia đều kia]
        bin_centers = np.sqrt(self.bin_edges[:-1] * self.bin_edges[1:]) #Mảng tâm của mỗi khoảng, lấu trung bình nhân để "đều"" trên logarit

        taus = [10.0, 50.0, 200.0, 1000.0] # 4 nhóm 
        self.decays = np.zeros((n_neurons, n_dt_bins)) # ma trận decays
        group_size = n_neurons // len(taus)

        # Duyệt qua từng giá trị tau
        for g, t in enumerate(taus):
            start = g * group_size # Neuron bắt đầu
            end = (g + 1) * group_size if g < len(taus) - 1 else n_neurons # Neuron cuối
            self.decays[start:end, :] = np.exp(-bin_centers / t)  # Tính bảng LUT
            
        self.n_bins = n_dt_bins

        # self.V = np.zeros(n_neurons) # Khởi tạo điện thế màng
        # self.spikes = np.zeros(n_neurons)# Khởi tạo spike

    # #Hàm đưa mạng về trạng thái ban đầu
    # def reset(self):
    #     self.V[:] = 0.0
    #     self.spikes[:] = 0.0

    def process_flow(self, flow_features):
        n_steps = len(flow_features) # mỗi packet 1 timestep
        V = np.zeros(self.N)
        spikes = np.zeros(self.N)
        
        # Lấy 3 đặc trưng timestamp,length, direction
        dt_all = flow_features[:, 0].astype(np.float64)
        length_all = flow_features[:, 1].astype(np.float64)
        dir_all = flow_features[:, 2].astype(np.float64)

        # Input 14 chiều
        X = np.zeros((n_steps, 14), dtype=np.float64)
        
        #Encoding 
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

        WinX = X @ self.W_in.T # -> ma trận n_steps * neurons

        #Tìm bin cho Δt
        decay_indices = np.searchsorted(self.bin_edges[1:], np.maximum(dt_all, 1e-6))
        decay_indices = np.clip(decay_indices, 0, self.n_bins - 1)

        scale = 2 ** self.res_shift #giá trị hiệu chỉnh spectral radius để giữ W_res {-1,0,1} chỉ mất 1 phép dịch bit 
        spike_counts = np.zeros(self.N, dtype=np.float64) # đếm tổng spike mỗi neuron
        states_over_time = np.zeros((n_steps, self.N)) # Lưu states theo thời gian n_steps và N neurons

        # Duyệt từng packet
        for i in range(n_steps):
            if i > 0:
                V *= self.decays[:, decay_indices[i]] #Cập nhật rò rỉ sau gói đầu

            recurrent = self.W_res @ spikes  
            V += WinX[i] + recurrent / scale  # cập nhật V

            fired = V > self.v_th #fire nếu vượt ngưỡng
            spikes = fired.astype(np.float64) # Cập nhật ma trận spikes thời điểm này
            V[fired] -= self.v_th # Reset
            
            spike_counts += spikes 
            states_over_time[i] = spike_counts.copy() #Cập nhật states

        return states_over_time #Trả về tổng spikes sau mỗi gói tin (tại timestep i)
```

- Hàm đánh giá khả năng phân loại
```python
from sklearn.linear_model import RidgeClassifier
from sklearn.model_selection import cross_val_score

def kernel_quality(state_matrix, labels):
    col_norms = np.linalg.norm(state_matrix, axis=0) # Tính norm L2 từng cột
    active = state_matrix[:, col_norms > 1e-10] # Chỉ giữ những neuron hoạt động

    if active.shape[1] == 0:
        return 0.0

    #Tạo classifier 
    clf = RidgeClassifier(random_state=42)
    
    try:
        scores = cross_val_score(clf, active, labels, cv=3) #croos-val 1/3 
        return float(np.mean(scores)) * 100.0 
    except Exception:
        return 0.0

```

- Hàm chọn fewshots:
```python
#Chọn 10 vectors dùng làm fewshot để so khớp cosine
# Dùng kmeans để tăng acc (chọn trực tiếp sẽ nhanh nhưng acc giảm)
from collections import Counter
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split

def get_kmeans_prototypes_and_test_idx(all_states_over_time, labels, n_shots=10, test_size=0.3):
    labels_arr = np.array(labels) # Danh sách label từng flow
    unique_classes = np.unique(labels_arr) # Danh sách label không trùng
    prototypes = [] # Mảng lưu prototypes
    test_idx = [] # idx các flow test

    # Duyệt từng label
    for label in unique_classes:
        idx_for_label = np.where(labels_arr == label)[0] # mảng idx các flow có cùng class
        if len(idx_for_label) < 2:
            continue
            
        train_i, test_i = train_test_split(idx_for_label, test_size=test_size, random_state=42) # 70% chọn fewshot, 30% test
        test_idx.extend(test_i)
        
        flow_vectors = [] 

        #Duyệt các flow
        for idx in train_i:
            active_steps = [s for s in all_states_over_time[idx][3:] if np.linalg.norm(s) > 1e-10]  #Lấy từ states bắt đầu hoạt động
            if active_steps:
                flow_vectors.append(np.mean(active_steps, axis=0)) #trung bình các cột của toàn bộ states
                
        if not flow_vectors:
            continue
            
        flow_vectors = np.array(flow_vectors)
        actual_k = min(n_shots, len(flow_vectors))
        
        if actual_k == 1:
            center = np.mean(flow_vectors, axis=0) # có thể n_shots = 1 thì sẽ lấy tbinh theo cột
            #Chuẩn hóa vector
            norm = np.linalg.norm(center)
            if norm > 1e-10:
                prototypes.append((label, center / norm)) 
        else:
            #Lấy actual-k vectors dùng so khớp cosine ( cần nhiều hơn 1 vì cùng 1 class có thể dữ liệu phân tán )
            kmeans = KMeans(n_clusters=actual_k, random_state=42, n_init='auto')
            kmeans.fit(flow_vectors)
            for center in kmeans.cluster_centers_:
                norm = np.linalg.norm(center)
                if norm > 1e-10:
                    prototypes.append((label, center / norm))
                    
    return prototypes, test_idx # Trả về các vector đại diện các class và chỉ số các flow chưa dùng chọn prototypes
```

- Hàm dùng fewshot phân loại class
```python
def continuous_few_shot_accuracy(all_states_over_time, labels, n_shots=10):
    prototypes, test_idx = get_kmeans_prototypes_and_test_idx(all_states_over_time, labels, n_shots)
    if not test_idx or not prototypes:
        return 0.0
        
    labels_arr = np.array(labels)
    correct = 0 #Đếm class đúng
    total = len(test_idx) #Tổng class
    
    #duyệt từng flow test
    for qi in test_idx:
        q_seq = all_states_over_time[qi] #flow qi
        votes = [] #Mảng đếm so khớp từng class qua từng timestep
        for step_state in q_seq[3:]: #Duyệt từng state (từng timestep)
            q_norm = np.linalg.norm(step_state)
            if q_norm < 1e-10: continue #Loại nếu state chưa hoạt động
            q_unit = step_state / q_norm
            
            best_sim, best_label = -2.0, None
            for label, proto in prototypes:
                sim = float(np.dot(q_unit, proto)) # tính cosine (vì đã chuẩn hóa nên u*v = cos(uv))
                if sim > best_sim:
                    best_sim, best_label = sim, label
            if best_label is not None:
                votes.append(best_label)
                
        if votes:
            final_pred = Counter(votes).most_common(1)[0][0] #Class có votes cao nhất
            if final_pred == labels_arr[qi]:
                correct += 1
                
    return (correct / total if total > 0 else 0.0) #Return acc
```

- Hàm chạy xử lý từng luồng:
```python
def run_reservoir_on_all_flows(flows, reservoir):
    final_states = np.zeros((len(flows), reservoir.N)) #Danh sách state cuổi của mỗi flow
    all_states_over_time = [] #Lưu toàn bộ states mỗi flow
    
    #Duyệt từng flow
    for i, flow in enumerate(flows):
        states_seq = reservoir.process_flow(flow)
        all_states_over_time.append(states_seq)
        final_states[i] = states_seq[-1]
        
    return final_states, all_states_over_time #Trả về danh sách state cuối mỗi flow và toàn bộ states mỗi flow
```

- Hàm tìm kết nối tốt nhất:
```python
def search_best_seed(flows, labels, seeds,
                     n_neurons=128, sparsity=0.12,
                     n_shots=5, res_shifts=[2, 3]):
    """
        flows:	Danh sách các flow mạng
        labels:	Nhãn tương ứng của từng flow
        seeds:	Danh sách seed muốn thử
        n_neurons:	Số neuron Reservoir
        sparsity:	Độ thưa của ma trận recurrent
        n_shots:	Số prototype tối đa mỗi lớp
        res_shifts:	Các giá trị scaling recurrent
    """
    configs = [(s, r) for s in seeds for r in res_shifts] # Danh sách cấu hình
    total = len(configs) # Tổng cấu hình
    print(f"\n{'=' * 60}")
    print(f"TÌM CẤU HÌNH TỐT NHẤT")
    print(f"   {len(seeds)} seeds × {len(res_shifts)} shifts = {total} cấu hình")
    print(f"   N={n_neurons}, sparsity={sparsity}")
    print(f"   res_shifts={list(res_shifts)}")
    print(f"   {len(flows)} flows, {len(set(labels))} lớp traffic")
    print(f"   Few-shot: {n_shots}-shot")
    print(f"{'=' * 60}\n")

    results = [] # Danh sách lưu kết quả
    t0 = time.time() # Thời gian chạy

    #Duyệt từng cấu hình
    for si, (seed, res_shift) in enumerate(configs):
        step = si + 1

        #Tạo mạng neurons
        reservoir = ReservoirSNN(
            n_neurons=n_neurons, n_inputs=14, sparsity=sparsity,
            v_th=3.0, seed=seed,
            res_shift=res_shift
        )

        #Chạy mạng neurons trên toàn bộ flows
        final_states, all_states = run_reservoir_on_all_flows(flows, reservoir)

        kq = kernel_quality(final_states, labels) #Tính KQ / final_states
        acc = continuous_few_shot_accuracy( 
            all_states, labels, n_shots=n_shots
        ) #Tính acc / fewshot

        results.append({
            'seed': seed,
            'res_shift': res_shift,
            'actual_rho': reservoir.actual_rho, #SR
            'rho_eff': reservoir.rho_effective, #SR hiệu dụng
            'kernel_quality': kq,
            'accuracy': acc
        }) #Them ket qua

        elapsed = time.time() - t0 #Tổng thời gian chạy hien tai
        eta = elapsed / step * (total - step) #Uoc tinh thoi gian con lai
        print(
            f"  [{step:>4}/{total}] seed={seed:<4d} >>={res_shift} "
            f"ρ_raw={reservoir.actual_rho:5.2f} ρ_eff={reservoir.rho_effective:5.2f}  "
            f"KQ={kq:6.2f}  Acc={acc*100:5.2f}%  "
            f"ETA {eta:.0f}s"
        )

    elapsed_total = time.time() - t0 #Tong thoi gian chay
    print(f"\n\nDone! {elapsed_total:.1f}s")
    results.sort(key=lambda r: (r['accuracy'], r['kernel_quality']), reverse=True)
    
    print(f"\n{'=' * 75}")
    print(f"TOP 10 CẤU HÌNH TỐT NHẤT")
    print(f"{'=' * 75}")
    print(f"{'#':>3}  {'Seed':>5}  {'>>':>2}  {'ρ_raw':>5}  {'ρ_eff':>5}  {'Kernel Quality':>15}  {'Accuracy (%)':>12}")
    print(f"{'-' * 75}")
    for i, r in enumerate(results[:10]):
        print(
            f"{i+1:>3}  {r['seed']:>5}  {r['res_shift']:>2}  "
            f"{r['actual_rho']:>5.2f}  {r['rho_eff']:>5.2f}  "
            f"{r['kernel_quality']:>15.2f}  "
            f"{r['accuracy']*100:>11.2f}%"
        )

    return results #Tra ve ket qua
```

- Hàm main:
```python
def main():
    #Các tham số
    PCAP_DIR         = os.path.join(os.path.dirname(__file__), "ISCX-VPN-NonVPN-2016-RAW")
    N_NEURONS        = 128        
    SPARSITY         = 0.13        
    SEEDS            = range(100)
    RES_SHIFTS       = [2, 3, 4] 
    MAX_PKTS_FILE    = 30000    
    MIN_PKTS_FLOW    = 15         
    MAX_PKTS_FLOW    = 50     
    MAX_FLOWS_LABEL  = 1000     
    FEW_SHOTS        = 10 



    print("=" * 60)
    print("RESERVOIR SEED SEARCH")
    print("   Pipeline: PCAP → LIF Reservoir (1 step/pkt, >>SHIFT) → Đánh giá")
    print("=" * 60)

    #Load dữ liệu
    t_load = time.time()
    flows, labels = load_flows(
        PCAP_DIR,
        max_packets_per_file=MAX_PKTS_FILE,
        min_pkts=MIN_PKTS_FLOW,
        max_pkts_per_flow=MAX_PKTS_FLOW,
        max_flows_per_label=MAX_FLOWS_LABEL,
    )
    print(f"Nạp dữ liệu: {time.time() - t_load:.1f}s")

    # if len(flows) < 20:
    #     return

    #Chạy lấy kết quả
    results = search_best_seed(
        flows, labels,
        seeds=SEEDS,
        n_neurons=N_NEURONS, sparsity=SPARSITY,
        n_shots=FEW_SHOTS,
        res_shifts=RES_SHIFTS,
    )

    #Cấu hình tốt nhất
    best = results[0]
    print(f"\n{'=' * 60}")
    print(f"KẾT QUẢ CUỐI CÙNG")
    print(f"   Seed:             {best['seed']}")
    print(f"   Right-shift:      >>{best['res_shift']} (÷{2**best['res_shift']})")
    print(f"   ρ_raw:            {best['actual_rho']:.2f}")
    print(f"   ρ_eff:            {best['rho_eff']:.2f}")
    print(f"   Kernel Quality:   {best['kernel_quality']:.2f}")
    print(f"   Few-shot Acc:     {best['accuracy']*100:.2f}%")
    print(f"{'=' * 60}")

    #Tạo lại mạng với seed tốt nhất
    reservoir = ReservoirSNN(
        n_neurons=N_NEURONS, n_inputs=14, sparsity=SPARSITY,
        v_th=3.0, seed=best['seed'],
        res_shift=best['res_shift']
    )

    #Dùng tạo prototype
    final_states, all_states_over_time = run_reservoir_on_all_flows(flows, reservoir)
    

    import matplotlib.pyplot as plt
    from sklearn.metrics import confusion_matrix, classification_report
    import seaborn as sns
    from collections import Counter

    km_prototypes, test_idx = get_kmeans_prototypes_and_test_idx(all_states_over_time, labels, FEW_SHOTS)
    
    prototypes_export = np.array([p[1] for p in km_prototypes]) #vector
    proto_labels_export = np.array([p[0] for p in km_prototypes]) #label

    #Lưu cấu hình
    out_file = "best_reservoir_config.npz"
    np.savez(
        out_file,
        W_res=reservoir.W_res,
        W_in=reservoir.W_in,
        decays=reservoir.decays,
        bin_edges=reservoir.bin_edges,
        seed=best['seed'],
        res_shift=best['res_shift'],
        actual_rho=best['actual_rho'],
        rho_effective=best['rho_eff'],
        sparsity=SPARSITY,
        n_neurons=N_NEURONS,
        v_threshold=reservoir.v_th,
        kernel_quality=best['kernel_quality'],
        accuracy=best['accuracy'],
        prototypes=prototypes_export,
        proto_labels=proto_labels_export
    )
    print(f"[+] Đã lưu cấu hình SNN và {len(prototypes_export)} Prototypes mẫu → {out_file}")
    print(f"   (Bao gồm: W_res, W_in, decays, và {len(prototypes_export)} vectors phục vụ So khớp Cosine)\n")
    
    print(f"[*] Đang vẽ Confusion Matrix từ kết quả mô phỏng...")
    
    #Confusion matrix
    labels_arr = np.array(labels)
    unique_labels = np.unique(labels_arr)
    
    y_true = []
    y_pred = []
    
    for qi in test_idx:
        q_seq = all_states_over_time[qi]
        
        votes = []
        for step_state in q_seq[3:]:
            q_norm = np.linalg.norm(step_state)
            if q_norm < 1e-10:
                continue
            q_unit = step_state / q_norm
            
            best_sim, best_label = -2.0, None
            for label, proto in km_prototypes:
                sim = float(np.dot(q_unit, proto))
                if sim > best_sim:
                    best_sim, best_label = sim, label
            if best_label is not None:
                votes.append(best_label)
                
        if not votes:
            final_pred = unique_labels[0]
        else:
            final_pred = Counter(votes).most_common(1)[0][0]
            
        y_true.append(labels_arr[qi])
        y_pred.append(final_pred)
        
    print("\n" + "=" * 60)
    print("CLASSIFICATION REPORT (DỰA TRÊN SEED TỐT NHẤT)")
    print("=" * 60)
    print(classification_report(y_true, y_pred, labels=unique_labels, zero_division=0))
    
    cm = confusion_matrix(y_true, y_pred, labels=unique_labels)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=unique_labels, yticklabels=unique_labels)
    plt.title(f"Confusion Matrix (Seed: {best['seed']}, >>{best['res_shift']}, ρ_eff: {best['rho_eff']:.2f}, Acc: {best['accuracy']*100:.2f}%)")
    plt.ylabel('Thực tế (True Label)')
    plt.xlabel('Dự đoán (Predicted Label)')
    plt.tight_layout()
    cm_file = "confusion_matrix.png"
    plt.savefig(cm_file)
    plt.close()
    
    print(f"\n[+] Đã lưu biểu đồ Confusion Matrix → {cm_file}")

if __name__ == "__main__":
    main()
```