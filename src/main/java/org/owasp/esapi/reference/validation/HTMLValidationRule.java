/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.reference.validation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Logger;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;


/**
 * A validator performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */
public class HTMLValidationRule extends StringValidationRule {
	
	/** OWASP AntiSamy markup verification policy */
	private static Policy antiSamyPolicy = null;
	private static final Logger LOGGER = ESAPI.getLogger( "HTMLValidationRule" ); 
	
	/**
	 * The vulnerable {@code htmlTitle}, {@code onsiteURL} and {@code offsiteURL}
	 * regular expressions, exactly as they appear in the stock
	 * {@code antisamy-esapi.xml} policy file shipped with every ESAPI 2.x release
	 * before 2.3.0.0, each paired with the corrected value from ESAPI 2.3.0.0
	 * (CVE-2022-24891). Among other flaws, the stock {@code onsiteURL} contains the
	 * character range {@code \#-~}, which includes {@code :}, so {@code javascript:}
	 * URLs were accepted as "onsite" links.
	 */
	private static final String[][] VULNERABLE_STOCK_REGEXPS = {
		{
			"name=\"htmlTitle\" value=\"[a-zA-Z0-9\\s-_',:\\[\\]!\\./\\\\\\(\\)]*\"",
			"name=\"htmlTitle\" value=\"[\\p{L}\\p{N}\\s\\-_',:\\[\\]!\\./\\\\\\(\\)&amp;]*\""
		},
		{
			"name=\"onsiteURL\" value=\"([\\w\\\\/\\.\\?=&amp;;\\#-~]+|\\#(\\w)+)\"",
			"name=\"onsiteURL\" value=\"^(?!//)(?![\\p{L}\\p{N}\\\\\\.\\#@\\$%\\+&amp;;\\-_~,\\?=/!]*(&amp;colon))[\\p{L}\\p{N}\\\\\\.\\#@\\$%\\+&amp;;\\-_~,\\?=/!]*\""
		},
		{
			"name=\"offsiteURL\" value=\"(\\s)*((ht|f)tp(s?)://|mailto:)[A-Za-z0-9]+[~a-zA-Z0-9-_\\.@#$%&amp;;:,\\?=/\\+!]*(\\s)*\"",
			"name=\"offsiteURL\" value=\"(\\s)*((ht|f)tp(s?)://|mailto:)[\\p{L}\\p{N}]+[\\p{L}\\p{N}\\p{Zs}\\.\\#@\\$%\\+&amp;;:\\-_~,\\?=/!\\(\\)]*(\\s)*\""
		}
	};

	static {
        InputStream resourceStream = null;
		try {
			resourceStream = ESAPI.securityConfiguration().getResourceStream("antisamy-esapi.xml");
		} catch (IOException e) {
			throw new ConfigurationException("Couldn't find antisamy-esapi.xml", e);
	            }
        if (resourceStream != null) {
        	try {
				antiSamyPolicy = loadAntiSamyPolicy(resourceStream);
			} catch (IOException e) {
				throw new ConfigurationException("Couldn't read antisamy-esapi.xml", e);
			} catch (PolicyException e) {
				throw new ConfigurationException("Couldn't parse antisamy policy", e);
		        }
			}
		}

	/**
	 * Reads an AntiSamy policy fully from the given stream, which is then closed,
	 * corrects any vulnerable stock regular expressions in it (see
	 * {@link #fixVulnerableStockRegexps(String)}) and parses the result.
	 *
	 * @param policyStream the AntiSamy policy file contents.
	 * @return the parsed AntiSamy policy.
	 * @throws IOException if the policy cannot be read.
	 * @throws PolicyException if the policy cannot be parsed.
	 */
	static Policy loadAntiSamyPolicy(InputStream policyStream) throws IOException, PolicyException {
		String policy;
		try {
			ByteArrayOutputStream contents = new ByteArrayOutputStream();
			byte[] buffer = new byte[4096];
			int count;
			while ((count = policyStream.read(buffer)) != -1) {
				contents.write(buffer, 0, count);
			}
			// ISO-8859-1 maps every byte to exactly one char and back again, so the
			// policy file passes through unchanged whatever its own encoding is.
			policy = new String(contents.toByteArray(), StandardCharsets.ISO_8859_1);
		} finally {
			policyStream.close();
		}
		policy = fixVulnerableStockRegexps(policy);
		return Policy.getInstance(new ByteArrayInputStream(policy.getBytes(StandardCharsets.ISO_8859_1)));
	}

	/**
	 * Replaces the vulnerable {@code htmlTitle}, {@code onsiteURL} and
	 * {@code offsiteURL} regular expressions of the stock {@code antisamy-esapi.xml}
	 * policy file shipped with ESAPI releases before 2.3.0.0 with their corrected
	 * values (CVE-2022-24891), so that applications still using a copy of that
	 * stock policy file are protected. Only the exact stock values are replaced;
	 * customized regular expressions are left unchanged.
	 *
	 * @param policy the AntiSamy policy file contents.
	 * @return the policy file contents with any vulnerable stock regular
	 *         expressions corrected.
	 */
	static String fixVulnerableStockRegexps(String policy) {
		String fixed = policy;
		for (String[] regexp : VULNERABLE_STOCK_REGEXPS) {
			fixed = fixed.replace(regexp[0], regexp[1]);
		}
		return fixed;
	}

	public HTMLValidationRule( String typeName ) {
		super( typeName );
	}
	
	public HTMLValidationRule( String typeName, Encoder encoder ) {
		super( typeName, encoder );
	}

	public HTMLValidationRule( String typeName, Encoder encoder, String whitelistPattern ) {
		super( typeName, encoder, whitelistPattern );
	}
	
    /**
     * {@inheritDoc}
     */
	@Override
	public String getValid( String context, String input ) throws ValidationException {
		return invokeAntiSamy( context, input );
	}
		
    /**
     * {@inheritDoc}
     */
	@Override
	public String sanitize( String context, String input ) {
		String safe = "";
		try {
			safe = invokeAntiSamy( context, input );
		} catch( ValidationException e ) {
			// just return safe
		}
		return safe;
	}

	/**
	 * Determines how AntiSamy scan errors are handled. When this returns
	 * {@code true} (the default), any AntiSamy scan errors are only logged and the
	 * cleaned (sanitized) HTML is returned. When this returns {@code false}, any
	 * AntiSamy scan errors result in a {@code ValidationException} being thrown.
	 * <p>
	 * Subclasses may override this to return {@code false} so that any AntiSamy
	 * scan errors always result in a {@code ValidationException}. (ESAPI's own
	 * {@code DefaultValidator.isValidSafeHTML} implementation does this so that it
	 * fails closed; see GitHub Security Advisory GHSA-r68h-jhhj-9jvm.)
	 *
	 * @return {@code true} if AntiSamy scan errors should only be logged and the
	 *         cleaned HTML returned; {@code false} if they should cause a
	 *         {@code ValidationException} to be thrown.
	 */
	protected boolean legacyHtmlValidation() {
		return true;
	}

	private String invokeAntiSamy( String context, String input ) throws ValidationException {
		// CHECKME should this allow empty Strings? "   " us IsBlank instead?
	    if ( StringUtilities.isEmpty(input) ) {
			if (allowNull) {
				return null;
			}
			throw new ValidationException( context + " is required", "AntiSamy validation error: context=" + context + ", input=" + input, context );
	    }
	    
		String canonical = super.getValid( context, input );

		try {
			AntiSamy as = new AntiSamy();
			CleanResults test = as.scan(canonical, antiSamyPolicy);
			
			List<String> errors = test.getErrorMessages();
			if ( !errors.isEmpty() ) {
				if ( !legacyHtmlValidation() ) {
					throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" + context + " errors=" + errors, context );
				}
				LOGGER.info( Logger.SECURITY_FAILURE, "Cleaned up invalid HTML input: " + errors );
			}
			
			return test.getCleanHTML().trim();
			
		} catch (ScanException e) {
			throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input: context=" + context + " error=" + e.getMessage(), e, context );
		} catch (PolicyException e) {
			throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" + context + " error=" + e.getMessage(), e, context );
		}
	}
}

