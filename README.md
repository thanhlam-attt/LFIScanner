# LFIScanner

## 🚀 Mô tả
Tool python tự động scan **Local File Inclusion (LFI) / Path Traversal** trong request dựa trên file requests.txt, sử dụng wordlist payload (có thể tự chọn).

<img width="719" height="400" alt="ảnh" src="https://github.com/user-attachments/assets/464d339c-8ba9-42c3-a79b-aeb440a5e9a9" />

## 🛠️ Ví dụ sử dụng
```python3 LFIScanner.py --request=request.txt --payloads=LFI_payloads.txt --proxy=127.0.0.1:8080 --outfile=hehe.txt```
