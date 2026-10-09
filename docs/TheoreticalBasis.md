- Mạng Reservoir SNN sử dụng LIF chuẩn:

$$
V[t] = \lambda V[t-1] + W_{in}x[t] + W_{res}s[t-1]
$$

$$
s[t] =
\begin{cases}
1, & \text{if } V[t] > V_{th} \\
0, & \text{o.w }
\end{cases}
$$

+Sau khi phát spike, neuron thực hiện **soft-reset**:

$$
V[t] \leftarrow V[t] - V_{th}
$$

- λ (hệ số rò rỉ):

$$
V ← V·exp(−Δt/τ) (= V.λ)
$$

+exp(−Δt/τ) ~ λ tính sẵn trong 1 bảng LUT với 4 tham số τ khác nhau cho mỗi 1/4 neurons: τ  = [10, 50, 200, 1000]


- Một flow dạng 
$$ 
F = \{p_1,p_2,\ldots,p_T\}
$$

+với thời gian xuất hiện:

$$
t_1,t_2,\ldots,t_T
$$

$$
\Delta t_i=t_i-t_{i-1}
$$

- Đầu vào là chuỗi 14 số {0, 1} dựa trên 3 đặc trưng [Δt,length,direction]:

+Với thời gian giữa 2 packet:
$$
x_{\Delta t} =
[
\Delta t>\tau_1,\,
\Delta t>\tau_2,\,
\ldots,\,
\Delta t>\tau_6
]
$$
+Với packet length:
$$
x_L =
[
L>\theta_1,\,
L>\theta_2,\,
\ldots,\,
L>\theta_6
]
$$
+Hướng truyền:
$$
x_{dir}\in\{0,1\}
$$

- Cosine  Similarity:
$$
sim(q,p)
=
\frac{q\cdot p}
{\|q\|\|p\|}
$$