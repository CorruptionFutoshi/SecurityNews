# Security Feed

IPA、JPCERT/CC、JVN、JPCERT/CC Eyes、CISA KEV、Krebs on Security、Reddit r/netsec、Exploit Database の公開情報をまとめて読む個人用ニュースフィードです。[internet_news](https://github.com/drawcia0122/internet_news) の「重要な話題、カテゴリ別フィード、履歴、定期更新」という構成を参考にしています。記事の本文は転載せず、元記事へのリンクを表示します。

公開 URL: <https://CorruptionFutoshi.github.io/SecurityNews/>

## 機能

- 緊急の注意喚起と CISA KEV の新規登録を優先表示
- Exploit Database の新規登録と更新を専用欄で表示（30日分）。PoC 公開と実際の悪用確認は区別
- Krebs on Security の記事と Reddit r/netsec の週間上位投稿を表示
- 直近24時間、7日、30日での絞り込み
- カテゴリ・情報源・キーワード・CVE による検索
- 既読と保存済みの管理（ブラウザの `localStorage`。端末間では同期されません）
- 情報源ごとの取得失敗と最終確認時刻を表示

## ローカルで確認

Python 3.12 以降を使います。外部パッケージは不要です。

```sh
python -m unittest discover -s tests -v
python scripts/refresh.py
python -m http.server 8000
```

`http://localhost:8000` を開いてください。`file://` では JSON を読み込めません。

## GitHub Pages で公開

1. このリポジトリを GitHub の公開リポジトリの `main` ブランチに push します。
2. `Settings > Pages > Build and deployment > Source` を **GitHub Actions** にします。
3. `Actions` の **Refresh and deploy Security Feed** を手動実行するか、`main` への push による実行を待ちます。

`.github/workflows/pages.yml` が UTC 00:17、06:17、12:17、18:17 に情報を取得し、30日分の `data/feed.json` を更新して Pages に公開します。取得に成功した情報源だけ新規データに反映し、失敗した情報源の前回分は残します。すべて失敗した場合は公開を止め、前回のサイトを維持します。GitHub Actions の定時実行は遅延または実行漏れがあり得ます。

GitHub Pages のサイトは公開されます。非公開の資産情報や個人メモを `data/feed.json` や HTML に入れないでください。

## データ形式

`scripts/refresh.py` が公開 RSS/Atom、[CISA KEV の公式ミラー](https://github.com/cisagov/kev-data)、[Exploit Database の公式 CSV](https://gitlab.com/exploit-database/exploitdb/-/blob/main/files_exploits.csv)を取得します。Reddit は r/netsec の週間上位 RSS を使い、投票数や正確な順位は保存しません。Exploit Database は `date_added` と `date_updated` から直近30日の変更を表示します。タイトル、短い説明、日時、CVE、元記事 URL のみ保存します。情報の正確性や対策内容は必ずリンク先で確認してください。
