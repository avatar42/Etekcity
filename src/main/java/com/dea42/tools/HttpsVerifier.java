package com.dea42.tools;

import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class HttpsVerifier implements HostnameVerifier {

	private static HttpsVerifier instance;
	private static final Set<String> validHosts = new HashSet<String>();

	private HttpsVerifier() {
	};

	public boolean verify(String hostname, SSLSession session) {
		return true;
		// return validHosts.contains(hostname);
	}

	public static void addHost(String hostname) {
		validHosts.add(hostname);
	}

	public static synchronized HttpsVerifier getInstance() {
		if (instance == null)
			instance = new HttpsVerifier();

		return instance;

	}
}
