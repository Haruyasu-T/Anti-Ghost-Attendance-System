# デプロイ準備（担当C / C-8）

2026-08-22時点の公式情報で比較した。HTTPS、秘密値の管理、SQLiteの永続化を必須条件としている。

## 比較

| 候補 | HTTPS | 環境変数・秘密値 | SQLiteの永続化 | 無料利用 | 判断 |
|---|---|---|---|---|---|
| Render | 自動TLS、HTTPはHTTPSへリダイレクト | DashboardのEnvironmentで設定 | Free Web Serviceは永続ディスク不可 | 750時間/月。ただし15分無通信で停止し、再起動に約1分 | SQLiteのままでは不可。Postgres移行か有料ディスクが必要 |
| Railway | 自動SSL、提供ドメインあり | ServiceのVariablesで設定 | FreeでもVolume上限0.5GB | 月$1相当の無料クレジット | 小規模な実機試験の第一候補 |
| Fly.io | 証明書とVolumeを提供 | `fly secrets` で設定 | Volumeは$0.15/GB/月 | 常設の無条件無料枠ではなく従量課金 | 制御性は高いが今回の「無料枠」優先には不向き |

公式資料：
- Render: https://render.com/docs/web-services
- Render Free: https://render.com/docs/free
- Railway: https://docs.railway.com/pricing/plans
- Railway Networking: https://docs.railway.com/networking/public-networking
- Railway Variables: https://docs.railway.com/variables
- Fly.io: https://fly.io/docs/about/pricing/
- Fly.io Secrets: https://fly.io/docs/apps/secrets/

## 採用案

プロトタイプの実機試験は **Railway Free + Volume** を第一候補にする。SQLiteを継続でき、HTTPSと環境変数を利用できるため。ただし無料クレジットを超えれば停止または課金対象になるので、使用量アラートを設定する。

Renderを使う場合、無料Web ServiceのローカルSQLiteは再起動・再デプロイで消える。出席記録には利用せず、Postgresへ移行するか有料Persistent Diskを付ける。

## デプロイ前チェックリスト

1. B担当のDB初期化方法とDBパス環境変数が確定している。
2. 永続VolumeをDBファイルの保存先へマウントする。
3. Start Commandを `uvicorn app.main:app --host 0.0.0.0 --port $PORT` 相当にする。
4. ホスティング画面の秘密変数として以下を設定する。値はGitへコミットしない。
   - `TOKEN_SECRET`: 暗号論的乱数32バイト以上
   - `CAMPUS_IP_RANGES`: 実測した大学出口IPのCIDR
   - `TRUSTED_PROXY_COUNT`: 実際の信頼プロキシ段数。想定が1台でも実測して決める
   - QR・受付時間・レート制限の各設定
5. `/health` をヘルスチェックに設定する。
6. HTTPS URLでログインCookie、カメラ、QR読み取りを確認する。
7. 学内の複数地点・複数時刻で出口IPを確認し、CIDRを決める。
8. 学外回線で出席登録が必ず拒否されることを確認する。
9. `X-Forwarded-For` の実際の並びをログで確認してから `TRUSTED_PROXY_COUNT` を確定する。

## 未確定事項

`TRUSTED_PROXY_COUNT=1` はホスティング構成を確認する前に固定しない。値を誤ると攻撃者が追加した `X-Forwarded-For` を信頼する可能性がある。デプロイ後の観測とA担当の確認を完了条件とする。
