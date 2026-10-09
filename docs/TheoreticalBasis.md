- Mạng Reservoir SNN sử dụng LIF chuẩn:

    $$
    V[t] = \lambda V[t-1] + W_{in}x[t] + W_{res}s[t-1]
    $$

    $$
    s[t] =
    \begin{cases}
    1, & \text{if } V[t] > V_{th} \\
    0, & \text{otherwise}
    \end{cases}
    $$

    - Sau khi phát spike, neuron thực hiện **soft-reset**:

        $$
        V[t] \leftarrow V[t] - V_{th}
        $$

- **Hệ số rò rỉ \(\lambda\):**

    $$
    V ← V·exp(−Δt/τ) (= V.λ)
    $$

    - Giá trị \(\lambda\) được tính sẵn trong bảng LUT với 4 tham số \(\tau\) khác nhau cho mỗi nhóm \(1/4\) số neuron:

        $$
        \tau = [10, 50, 200, 1000]
        $$

- Một flow được biểu diễn dưới dạng:

    $$
    F = \{p_1,p_2,\ldots,p_T\}
    $$

    - Với thời gian xuất hiện của các packet:

        $$
        t_1,t_2,\ldots,t_T
        $$

    - Khoảng thời gian giữa hai packet liên tiếp:

        $$
        \Delta t_i = t_i - t_{i-1}
        $$

- **Đầu vào:** Chuỗi 14 giá trị nhị phân \(\{0,1\}\), được tạo từ 3 đặc trưng \([\Delta t, length, direction]\).

    - **Packet length:**

        $$
        x_L =
        [
        L>\theta_1,\,
        L>\theta_2,\,
        \ldots,\,
        L>\theta_6
        ]
        $$

    - **Thời gian giữa hai packet:**

        $$
        x_{\Delta t} =
        [
        \Delta t>\tau_1,\,
        \Delta t>\tau_2,\,
        \ldots,\,
        \Delta t>\tau_6
        ]
        $$

    - **Hướng truyền:**

        $$
        x_{dir}\in\{0,1\}
        $$

- **Cosine Similarity:**

    $$
    sim(q,p)
    =
    \frac{q\cdot p}
    {\|q\|\|p\|}
    $$

