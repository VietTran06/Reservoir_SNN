- Mạng Reservoir SNN sử dụng LIF chuẩn:

$$
V[t] = \lambda V[t-1] + W_{in}x[t] + W_{res}s[t-1]
$$

$$
s[t] =
\begin{cases}
1, & \text{nếu } V[t] > V_{th} \\
0, & \text{ngược lại}
\end{cases}
$$

Sau khi phát spike, neuron thực hiện **soft-reset**:

$$
V[t] \leftarrow V[t] - V_{th}
$$

- λ (hệ số rò rỉ):

$$
V ← V·exp(−Δt/τ)
$$

Δt tính sẵn trong 1 bảng LUT với 4 tham số τ khác nhau cho mỗi 1/4 neurons: τ  = [10, 50, 200, 1000]


