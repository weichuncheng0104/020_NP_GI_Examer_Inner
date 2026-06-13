# 020_NP_GI_Examer_Inner

> ⚙️ **本 repo 為自動產生物（generated），請勿手動編輯。**
> 所有檔案由處理層 pipeline（私有 Repo A `020_NP_GI_Examer`）的
> `script/0009_build_innersite.py`（知識站）與 `script/0010_build_manual.py`（PDF 手冊）
> 產生並覆寫；手動修改會在下次 build 被洗掉。

## 這是什麼

專科護理師（Nurse Practitioner, NP）甄審・胃腸肝膽科**知識整理站**的密碼鎖前端。

- 全站知識內容以 **AES-256-GCM（金鑰由 PBKDF2-SHA256 派生）客戶端加密**，本 repo 內僅含**密文**；
  無正確密碼則無法解密、無法閱讀。解密全在瀏覽器端進行，密碼不經任何伺服器、不留存。
- 另提供加密 PDF 手冊（`manual/np-gi-handbook.pdf`，PDF 原生 AES-256 密碼）供離線下載，
  以同一組密碼開啟。
- `meta.json` 內的 `salt` / `iterations` 為公開派生參數（非機密）。

## 版權與用途

非公開・私人考題及內容知識整理與確認使用；密碼保護下為非營利、無公開散布／非法擴散意圖之個人學習用途。

## 禁止事項

- 禁手動編輯本 repo 任何檔案（會被下次 build 覆寫）。
- 本 repo 不含任何明文知識內容、不含密碼或任何 secret。
