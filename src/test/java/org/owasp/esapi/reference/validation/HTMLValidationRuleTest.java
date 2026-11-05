/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2022 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
package org.owasp.esapi.reference.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;

/**
 * Tests that {@code HTMLValidationRule} corrects the vulnerable regular
 * expressions of the stock {@code antisamy-esapi.xml} policy file shipped with
 * ESAPI releases before 2.3.0.0 (CVE-2022-24891), which allowed
 * {@code javascript:} URLs in {@code href} attributes.
 */
public class HTMLValidationRuleTest {

    private static final String SAFE_TEXT = "This is safe from XSS. Trust us!";

    // The vulnerable regexps, exactly as they appear in configuration/esapi/antisamy-esapi.xml
    // of every ESAPI 2.x release before 2.3.0.0.
    private static final String STOCK_HTML_TITLE =
        "name=\"htmlTitle\" value=\"[a-zA-Z0-9\\s-_',:\\[\\]!\\./\\\\\\(\\)]*\"";
    private static final String STOCK_ONSITE_URL =
        "name=\"onsiteURL\" value=\"([\\w\\\\/\\.\\?=&amp;;\\#-~]+|\\#(\\w)+)\"";
    private static final String STOCK_OFFSITE_URL =
        "name=\"offsiteURL\" value=\"(\\s)*((ht|f)tp(s?)://|mailto:)[A-Za-z0-9]+[~a-zA-Z0-9-_\\.@#$%&amp;;:,\\?=/\\+!]*(\\s)*\"";

    // The corrected regexps, as in ESAPI 2.3.0.0 (and in the test antisamy-esapi.xml).
    private static final String FIXED_HTML_TITLE =
        "name=\"htmlTitle\" value=\"[\\p{L}\\p{N}\\s\\-_',:\\[\\]!\\./\\\\\\(\\)&amp;]*\"";
    private static final String FIXED_ONSITE_URL =
        "name=\"onsiteURL\" value=\"^(?!//)(?![\\p{L}\\p{N}\\\\\\.\\#@\\$%\\+&amp;;\\-_~,\\?=/!]*(&amp;colon))[\\p{L}\\p{N}\\\\\\.\\#@\\$%\\+&amp;;\\-_~,\\?=/!]*\"";
    private static final String FIXED_OFFSITE_URL =
        "name=\"offsiteURL\" value=\"(\\s)*((ht|f)tp(s?)://|mailto:)[\\p{L}\\p{N}]+[\\p{L}\\p{N}\\p{Zs}\\.\\#@\\$%\\+&amp;;:\\-_~,\\?=/!\\(\\)]*(\\s)*\"";

    /**
     * @return the (already corrected) antisamy-esapi.xml policy used by the tests.
     */
    private static String correctedPolicy() throws IOException {
        InputStream in = ESAPI.securityConfiguration().getResourceStream("antisamy-esapi.xml");
        assertNotNull("antisamy-esapi.xml not found", in);
        try {
            ByteArrayOutputStream contents = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int count;
            while ((count = in.read(buffer)) != -1) {
                contents.write(buffer, 0, count);
            }
            return new String(contents.toByteArray(), StandardCharsets.ISO_8859_1);
        } finally {
            in.close();
        }
    }

    /**
     * @return the test policy with its regexps put back to the vulnerable stock
     *         values of ESAPI releases before 2.3.0.0.
     */
    private static String stockPolicy() throws IOException {
        String corrected = correctedPolicy();
        assertTrue(corrected.contains(FIXED_HTML_TITLE));
        assertTrue(corrected.contains(FIXED_ONSITE_URL));
        assertTrue(corrected.contains(FIXED_OFFSITE_URL));
        return corrected.replace(FIXED_HTML_TITLE, STOCK_HTML_TITLE)
                        .replace(FIXED_ONSITE_URL, STOCK_ONSITE_URL)
                        .replace(FIXED_OFFSITE_URL, STOCK_OFFSITE_URL);
    }

    private static InputStream asStream(String policy) {
        return new ByteArrayInputStream(policy.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static String scan(String html, Policy policy) throws Exception {
        return new AntiSamy().scan(html, policy).getCleanHTML().trim();
    }

    private static String link(String href) {
        return "<a href=\"" + href + "\">" + SAFE_TEXT + "</a>";
    }

    @Test
    public void testFixVulnerableStockRegexps() throws Exception {
        String stock = stockPolicy();
        assertTrue(stock.contains(STOCK_HTML_TITLE));
        assertTrue(stock.contains(STOCK_ONSITE_URL));
        assertTrue(stock.contains(STOCK_OFFSITE_URL));

        String fixed = HTMLValidationRule.fixVulnerableStockRegexps(stock);
        assertFalse(fixed.contains(STOCK_HTML_TITLE));
        assertFalse(fixed.contains(STOCK_ONSITE_URL));
        assertFalse(fixed.contains(STOCK_OFFSITE_URL));
        assertTrue(fixed.contains(FIXED_HTML_TITLE));
        assertTrue(fixed.contains(FIXED_ONSITE_URL));
        assertTrue(fixed.contains(FIXED_OFFSITE_URL));
        // Nothing but the vulnerable regexps is changed.
        assertEquals(correctedPolicy(), fixed);
    }

    @Test
    public void testFixVulnerableStockRegexpsLeavesCustomizedRegexpsUnchanged() throws Exception {
        String customOnsiteURL = "name=\"onsiteURL\" value=\"([\\w\\\\/\\.\\?=&amp;;\\#-~]+|\\#(\\w)+|custom)\"";
        String customized = stockPolicy().replace(STOCK_ONSITE_URL, customOnsiteURL);
        assertTrue(customized.contains(customOnsiteURL));

        String fixed = HTMLValidationRule.fixVulnerableStockRegexps(customized);
        assertTrue(fixed.contains(customOnsiteURL));
        assertFalse(fixed.contains(FIXED_ONSITE_URL));
        // The remaining stock regexps are still corrected.
        assertTrue(fixed.contains(FIXED_HTML_TITLE));
        assertTrue(fixed.contains(FIXED_OFFSITE_URL));

        // An already corrected policy is left exactly as it is.
        String corrected = correctedPolicy();
        assertEquals(corrected, HTMLValidationRule.fixVulnerableStockRegexps(corrected));
    }

    // CVE-2022-24891: the stock onsiteURL regexp accepted javascript: URLs.
    @Test
    public void testStockPolicyJavaScriptURL() throws Exception {
        String badVoodoo = link("javascript:alert(1)");

        // The stock policy, parsed as-is, lets the javascript: URL through ...
        Policy vulnerable = Policy.getInstance(asStream(stockPolicy()));
        assertTrue(scan(badVoodoo, vulnerable).contains("javascript:alert(1)"));

        // ... but not once HTMLValidationRule has loaded (and corrected) it.
        Policy corrected = HTMLValidationRule.loadAntiSamyPolicy(asStream(stockPolicy()));
        assertEquals(SAFE_TEXT, scan(badVoodoo, corrected));
    }

    @Test
    public void testStockPolicyJavaScriptURLVariants() throws Exception {
        Policy corrected = HTMLValidationRule.loadAntiSamyPolicy(asStream(stockPolicy()));

        String[] badHrefs = {
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "javascript&colon;alert&lpar;1&rpar;",
            "javascript&#58;alert(1)",
            "javascript&#x3a;alert(1)",
            "javascript&#X3A;alert(1)",
            "vbscript:msgbox(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "//evil.example.com/xss.html"
        };
        for (String href : badHrefs) {
            assertEquals(href, SAFE_TEXT, scan(link(href), corrected));
        }

        String[] goodHrefs = {
            "/esapi/docs/index.html",
            "index.html?page=2#top",
            "#top",
            "http://www.aspectsecurity.com",
            "https://www.owasp.org/index.php/ESAPI",
            "mailto:esapi@owasp.org"
        };
        for (String href : goodHrefs) {
            assertEquals(href, link(href), scan(link(href), corrected));
        }
    }

    @Test
    public void testLoadAntiSamyPolicyClosesStream() throws Exception {
        final boolean[] closed = { false };
        InputStream in = new ByteArrayInputStream(correctedPolicy().getBytes(StandardCharsets.ISO_8859_1)) {
            @Override
            public void close() throws IOException {
                closed[0] = true;
                super.close();
            }
        };
        assertNotNull(HTMLValidationRule.loadAntiSamyPolicy(in));
        assertTrue(closed[0]);
    }
}
