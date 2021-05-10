
# Return-Oriented Programming (ROP) Explanation
___

### Tại sao có kỹ thuật tấn công ROP?

Sự xuất hiện của các cơ chế bảo vệ như Non-executable (NX) hay Data Execution Prevention (DEP) giúp chống thực thi code ở vùng nhớ không cho phép. Có nghĩa là khi chúng ta khai thác lỗ hổng Buffer Overflow (BOF) của một chương trình, nếu chương trình này có cơ chế bảo vệ NX hay DEP thì shellcode chúng ta chèn vào xem như vô dụng - bởi vì vùng nhớ lưu shellcode đã bị đánh dấu là không được thực thi.

ROP là một kỹ thuật tấn công tận dụng các đoạn code có sẵn của chương trình (.code section) Ý tưởng chính là sử dụng các gadget hiện có trong chương trình trên cơ sở tràn bộ đệm ngăn xếp. Thay đổi giá trị của một số thanh ghi hoặc các biến để điều khiển luồng thực thi của chương trình. Gadget là các chuỗi lệnh kết thúc bằng ret. Thông qua các chuỗi lệnh này, chúng ta có thể sửa đổi nội dung của một số địa chỉ nhất định để tạo điều kiện thuận lợi cho việc kiểm soát luồng thực thi của chương trình.

Nó được gọi là ROP vì cốt lõi là sử dụng lệnh ret trong tập lệnh để thay đổi thứ tự thực thi của luồng lệnh. Các cuộc tấn công ROP thường phải đáp ứng các điều kiện sau:

- Có một phần tràn trong chương trình và địa chỉ trả về có thể được kiểm soát.

- Bạn có thể tìm thấy các gadget đáp ứng các điều kiện và địa chỉ của các gadget tương ứng.

## ret2text


