# 学内Wi-Fi連動 QR出席管理システム

QRコードを「学内Wi-Fi環境下」で読み込んだときのみ出席として認めることで，代返（なりすまし出席）を防ぐ出席管理システムのプロトタイプです．

## 特徴
- 動的QR（数十秒ごとにトークン更新）でスクリーンショット転送を無効化
- サーバー側でのアクセス元IP検証（クライアント自己申告は信用しない）
- 出席記録の一意制約による二重出席防止

セキュリティ職志望メンバーが，具体的な脅威モデルに基づいて設計・実装したことを示すポートフォリオプロジェクトです．詳細な脅威モデルと設計判断は [docs/](docs/) を参照してください．

## 技術スタック
- Python 3.11+
- FastAPI
- SQLite
- HTML / JavaScript

## セットアップ
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## 開発ルール
- `main` への直接コミット禁止．機能ブランチ + PRレビューで運用．
- 詳細は [CLAUDE.md](CLAUDE.md) を参照．
