package org.owasp.esapi;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.owasp.esapi.errors.ConfigurationException;


public class ESAPIVerifyAllowedMethodsTest {

	@Test (expected = IllegalArgumentException.class)
	public void verifyNulParamThrows() {
		ESAPI.isMethodExplicityEnabled(null);
	}

	@Test (expected = IllegalArgumentException.class)
	public void verifyEmptyNoWhitespaceParameterThrows() {
		ESAPI.isMethodExplicityEnabled("");
	}

	@Test (expected = IllegalArgumentException.class)
	public void verifyEmptyOnlyWhitespaceParameterThrows() {
		ESAPI.isMethodExplicityEnabled("   ");
	}

	@Test (expected = IllegalArgumentException.class)
	public void verifyEmptyOnlyTabWhitespaceParameterThrows() {
		ESAPI.isMethodExplicityEnabled("\t");
	}

	@Test (expected = IllegalArgumentException.class)
	public void verifyEmptyOnlyNewlineWhitespaceParameterThrows() {
		ESAPI.isMethodExplicityEnabled("\n");
	}



	@Test (expected = IllegalArgumentException.class)
	public void verifyNonEsapiPackageParameterThrows() {
		ESAPI.isMethodExplicityEnabled("com.myPackage.myScope.method");
	}
	@Test
	public void verifyUnknownMethodFailsEnableCheck() {
		Assert.assertFalse(ESAPI.isMethodExplicityEnabled("org.owasp.esapi.reference.DefaultEncoder.encodeForSQ"));
	}

	@Test
	public void verifyDefinedRestrictionIsCaught() {
		Assert.assertTrue(ESAPI.isMethodExplicityEnabled("org.owasp.esapi.reference.DefaultEncoder.encodeForSQL"));
	}

	@Test
	public void testMissingPropertyReturnsFalse() {
		try {
		// Spy on a wrapper around the real configuration (rather than a bare mock) so that
		// any other thread using ESAPI while it is overridden still sees a working configuration.
		SecurityConfiguration mockConfig = Mockito.spy(new SecurityConfigurationWrapper(ESAPI.securityConfiguration()));
		Mockito.doThrow(ConfigurationException.class).when(mockConfig).getStringProp("ESAPI.dangerouslyAllowUnsafeMethods.methodNames");
		ESAPI.override(mockConfig);

		Assert.assertFalse(ESAPI.isMethodExplicityEnabled("org.owasp.esapi.thisValueDoesNotMatter"));
		Mockito.verify(mockConfig, Mockito.times(1)).getStringProp("ESAPI.dangerouslyAllowUnsafeMethods.methodNames");
		} finally {
			ESAPI.override(null);
		}

	}

	@Test
	public void testUnreadablePropertyReturnsFalse() {
		// E.g., a DefaultSecurityConfiguration created from a Properties object throws
		// a NullPointerException from getStringProp. The check must fail closed.
		try {
		// Spy on a wrapper around the real configuration (rather than a bare mock) so that
		// any other thread using ESAPI while it is overridden still sees a working configuration.
		SecurityConfiguration mockConfig = Mockito.spy(new SecurityConfigurationWrapper(ESAPI.securityConfiguration()));
		Mockito.doThrow(NullPointerException.class).when(mockConfig).getStringProp("ESAPI.dangerouslyAllowUnsafeMethods.methodNames");
		ESAPI.override(mockConfig);

		Assert.assertFalse(ESAPI.isMethodExplicityEnabled("org.owasp.esapi.reference.DefaultEncoder.encodeForSQL"));
		Mockito.verify(mockConfig, Mockito.times(1)).getStringProp("ESAPI.dangerouslyAllowUnsafeMethods.methodNames");
		} finally {
			ESAPI.override(null);
		}

	}

}
