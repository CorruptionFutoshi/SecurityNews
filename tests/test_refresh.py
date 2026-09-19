import json
import unittest
from datetime import datetime, timezone
from scripts.refresh import SOURCES, parse_exploit_db, parse_ipa_urgent_urls, parse_kev, parse_reddit, parse_xml_feed, plain_text


class FeedParsingTests(unittest.TestCase):
    def test_rdf_feed_normalizes_and_extracts_cve(self):
        payload = b'''<?xml version="1.0" encoding="utf-8"?>
        <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                 xmlns:dc="http://purl.org/dc/elements/1.1/">
          <item><title>Test CVE-2026-12345</title>
            <link>https://jvn.jp/jp/JVN12345678/index.html</link>
            <dc:date>2026-09-18T12:30:00+09:00</dc:date>
            <description>&lt;p&gt;Security &amp;amp; update&lt;/p&gt;</description>
          </item>
        </rdf:RDF>'''
        item = parse_xml_feed(payload, SOURCES[2])[0]
        self.assertEqual(item["cves"], ["CVE-2026-12345"])
        self.assertEqual(item["description"], "Security & update")
        self.assertEqual(item["publishedAt"], "2026-09-18T03:30:00Z")

    def test_atom_feed_uses_link_attribute(self):
        payload = b'''<feed xmlns="http://www.w3.org/2005/Atom">
          <entry><title>Incident report</title>
            <link rel="alternate" href="https://blogs.jpcert.or.jp/ja/test.html" />
            <updated>2026-09-18T00:00:00Z</updated><summary>Analysis</summary>
          </entry></feed>'''
        item = parse_xml_feed(payload, SOURCES[3])[0]
        self.assertEqual(item["category"], "analysis")
        self.assertEqual(item["url"], "https://blogs.jpcert.or.jp/ja/test.html")

    def test_kev_is_marked_as_exploited(self):
        payload = json.dumps({"vulnerabilities": [{
            "cveID": "CVE-2026-9999", "vendorProject": "Example", "product": "Device",
            "dateAdded": "2026-09-18", "shortDescription": "Exploited in the wild",
        }]}).encode()
        item = parse_kev(payload, SOURCES[4])[0]
        self.assertEqual(item["priority"], "exploited")
        self.assertEqual(item["cves"], ["CVE-2026-9999"])
        self.assertIn("CVE-2026-9999", item["url"])

    def test_html_is_reduced_to_plain_text(self):
        self.assertEqual(plain_text('<script>alert(1)</script><b>Notice</b>'), 'alert(1) Notice')

    def test_ipa_urgent_label_comes_from_index(self):
        payload = b'<li class="news-list__item" data-search="urgent"><a href="/security/security-alert/2026/example.html">Alert</a></li>'
        self.assertEqual(parse_ipa_urgent_urls(payload), {'https://www.ipa.go.jp/security/security-alert/2026/example.html'})

    def test_exploit_db_uses_change_date_without_claiming_active_exploitation(self):
        today = datetime.now(timezone.utc).date().isoformat()
        payload = ("id,description,date_added,date_updated,codes,platform,type\n"
                   f'12345,"Product - Remote Code Execution",2020-01-01,{today},CVE-2026-12345,linux,remote\n').encode()
        source = next(source for source in SOURCES if source['id'] == 'exploit-db')
        item = parse_exploit_db(payload, source)[0]
        self.assertEqual(item['url'], 'https://www.exploit-db.com/exploits/12345')
        self.assertEqual(item['priority'], 'exploit-published')
        self.assertEqual(item['category'], 'exploit')
        self.assertIn('更新', item['description'])
        self.assertEqual(item['cves'], ['CVE-2026-12345'])

    def test_reddit_post_is_labeled_as_community_without_score(self):
        payload = b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry>
          <title>Research discussion</title>
          <link rel="alternate" href="https://www.reddit.com/r/netsec/comments/abc/test/" />
          <updated>2026-09-18T00:00:00Z</updated><content>submitted by user</content>
        </entry></feed>'''
        source = next(source for source in SOURCES if source['id'] == 'reddit-netsec')
        item = parse_reddit(payload, source)[0]
        self.assertEqual(item['category'], 'community')
        self.assertEqual(item['priority'], 'normal')
        self.assertNotIn('submitted by', item['description'])


if __name__ == "__main__":
    unittest.main()
