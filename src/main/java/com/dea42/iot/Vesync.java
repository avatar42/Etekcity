package com.dea42.iot;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.omg.CORBA.BAD_PARAM;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.dea42.tools.HttpsVerifier;
import com.dea42.tools.Utils;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * Simple Java interface for Vesync VeSyncOutlet7A smart plugs based on these
 * https://github.com/mikeczabator/python-vesync-etekcity-api/blob/master/api.py
 * https://github.com/webdjoe/pyvesync/blob/master/src/pyvesync/vesyncoutlet.py
 * 
 * @author avata
 *
 */
public class Vesync {
	private final Logger log = LoggerFactory.getLogger(getClass());
	private static final String BASE_URL = "https://smartapi.vesync.com";
	private static final String LOGIN_SUB_URL = "/vold/user/login";

	/**
	 * @param login the login to set
	 */
	public void setLogin(String login) {
		this.login = login;
	}

	/**
	 * @param password the password to set
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	private static final String GETDEVICES_SUB_URL = "/vold/user/devices";
	private static final String DEVICE_SUB_URL = "/v1/device/";
	private static final String COMMAND_SUB_URL = "/v1/wifi-switch-1.3/";
	protected static final String BUNDLENAME = "Etekcity";
	// saved / cached from get devices call
	public static final String DEVICE_JSON = "devices.json";
	// seconds to pause between sending off and on for reset
	private int pauseSecs = 20;
	private String tk;
	private String accountID;
	private String login;
	private String password;
	private ResourceBundle bundle;
	private Map<String, String> deviceMap = new HashMap<String, String>();

	private int timeout = 15000; // in milisecs
	private Boolean followRedirects = false;
	private String contentType = "text/text;";
	private String keyFile = "keystorefile.store";
	private String keyPass = "password";

	// checkable return values
	private Date modDate = null;
	private long len = 0;
	private int respCode = 0;
	private boolean ignoreRespCode = false;
	private Map<String, List<String>> conHeaders;
	private Header[] respHeaders;

	// globals
	private SSLSocketFactory sslSocketFactory;

	private SimpleDateFormat headerDateFormatFull = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz");
	private SimpleDateFormat headerDateFormat = new SimpleDateFormat("dd MMM yyyy HH:mm:ss zzz");

	private String userAgentString = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36";

	public Vesync() {
		this.loadBundle();
	}

	private void setRespCode(int respCode) {
		this.respCode = respCode;
	}

	private void loadBundle() {
		try {
			bundle = ResourceBundle.getBundle(BUNDLENAME);
			login = bundle.getString("login");
			password = bundle.getString("password");
		} catch (Exception e) {
			log.warn(BUNDLENAME + ".properties not found. login and password need to be passed on the command line");
		}
	}

	/**
	 * Log onto the Vesync API server to get and access token.
	 * 
	 * @return true if login was successful otherwise false.
	 */
	public boolean jsonLogin() {
		// payload =
		// json.dumps({"account":username,"devToken":"","password":hashlib.md5(password.encode('utf-8')).hexdigest()})
		// account = requests.post(BASE_URL + "/vold/user/login", verify=False,
		// data=payload).json()
		if (accountID != null && accountID.length() > 1)
			return true;

		JSONObject params = new JSONObject();
		params.put("account", login);
		params.put("devToken", "");
		params.put("password", password);
		String s = null;

		try {
			URL url = new URL(BASE_URL + LOGIN_SUB_URL);
			s = sendReq(params, url, "POST");

			// sent response to auth request
			JSONObject resp = JSONObject.fromObject(s);

			tk = resp.getString("tk");
			accountID = resp.getString("accountID");

			return accountID != null && accountID.length() > 1;
		} catch (Exception e) {
			log.error("Failed to parse response:" + s, e);
		}
		return false;
	}

	private void initSSL(URL url) {
		if (true) {
			log.info("Adding SSL settings");
			// setKeystore();
			HttpsVerifier.addHost(url.getHost());

			HttpsURLConnection.setDefaultHostnameVerifier(HttpsVerifier.getInstance());

			// since most of the stuff we hit is self signed or expired just
			// trust them
			try {
				final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
					public void checkClientTrusted(final X509Certificate[] chain, final String authType)
							throws CertificateException {
					}

					public void checkServerTrusted(final X509Certificate[] chain, final String authType)
							throws CertificateException {
					}

					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}

				} };

				final SSLContext sslContext = SSLContext.getInstance("SSL");
				sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
				sslSocketFactory = sslContext.getSocketFactory();
				Authenticator.setDefault(new Authenticator() {

					protected PasswordAuthentication getPasswordAuthentication() {
						return new PasswordAuthentication(login, password.toCharArray());
					}
				});
			} catch (KeyManagementException |

					NoSuchAlgorithmException e) {
				log.error("Failed reading url", e);
			}
		}
	}

	private Date parseDate(String s) {
		Date modDate = null;
		try {
			modDate = headerDateFormatFull.parse(s);
		} catch (ParseException e) {
			// parse without day of week since some misspell them
			int i = s.indexOf(",");
			if (i > -1) {
				s = s.substring(i);
			}
			try {
				modDate = headerDateFormat.parse(s.trim());
			} catch (Exception e1) {
				log.warn("Exception parsing:" + s);
			}
		}

		return modDate;
	}

	/**
	 * Try to install cert in app's keyFile as last final option to get secure
	 * connection
	 * 
	 * @param con connection we are trying to fix
	 * @param url associated with con
	 * @param e   Exception that triggered this work around
	 * @throws KeyManagementException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	private void tryTlsPlusCertInstall(HttpURLConnection con, URL url, Exception e) throws KeyManagementException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		if (url.getProtocol().equals("https") && keyFile != null) {
			log.error("Trying to install cert as last final option", e);
			int port = url.getPort();
			if (port == -1)
				port = url.getDefaultPort();

			// SSLSocketFactory sf = install(url.getHost(), port, keyPass,
			// keyFile);
			char[] passphrase = keyPass.toCharArray();

			File file = new File(keyFile);
			if (file.isFile() == false) {
				char SEP = File.separatorChar;
				File dir = new File(System.getProperty("java.home") + SEP + "lib" + SEP + "security");
				file = new File(dir, keyFile);
				if (file.isFile() == false) {
					file = new File(dir, "cacerts");
				}
			}
			log.info("Loading KeyStore " + file + "...");
			InputStream in = new FileInputStream(file);
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			try {
				ks.load(in, passphrase);
			} catch (Exception e1) {
				log.error(keyPass, e1);
			}
			in.close();

			SSLContext context = SSLContext.getInstance("TLS");
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(ks);
			X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
			SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
			context.init(null, new TrustManager[] { tm }, null);
			SSLSocketFactory factory = context.getSocketFactory();

			log.info("Opening connection to " + url.getHost() + ":" + port + "...");
			SSLSocket socket = (SSLSocket) factory.createSocket(url.getHost(), port);
			socket.setSoTimeout(10000);
			try {
				log.info("Starting SSL handshake...");
				socket.startHandshake();
				socket.close();
				log.info("");
				log.info("No errors, certificate is already trusted");
			} catch (SSLException e1) {
				log.error("", e1);

				X509Certificate[] chain = tm.chain;
				if (chain == null) {
					log.info("Could not obtain server certificate chain");
					factory = null;
				} else {

					log.info("");
					log.info("Server sent " + chain.length + " certificate(s):");
					log.info("");
					MessageDigest sha1 = MessageDigest.getInstance("SHA1");
					MessageDigest md5 = MessageDigest.getInstance("MD5");
					for (int i = 0; i < chain.length; i++) {
						X509Certificate cert = chain[i];
						log.info(" " + (i + 1) + " Subject " + cert.getSubjectDN());
						log.info("   Issuer  " + cert.getIssuerDN());
						sha1.update(cert.getEncoded());
						log.info("   sha1    " + Utils.toHexString(sha1.digest()));
						md5.update(cert.getEncoded());
						log.info("   md5     " + Utils.toHexString(md5.digest()));
						log.info("");
					}
					int k = 0;
					X509Certificate cert = chain[k];
					String alias = url.getHost() + "-" + (k + 1);
					ks.setCertificateEntry(alias, cert);

					OutputStream out = new FileOutputStream(keyFile);
					ks.store(out, passphrase);
					out.close();

					log.info("");
					log.info(cert.toString());
					log.info("");
					log.info("Added certificate to keystore '" + keyFile + "' using alias '" + alias + "'");
				}
			}

			if (factory != null)
				HttpsURLConnection.setDefaultSSLSocketFactory(factory);

			setRespCode(con.getResponseCode());
		} else {
			log.error("Failed to connect to:" + url, e);
		}

	}

	/**
	 * Get the first (usually only) header value for a given key
	 * 
	 * @param asClass    Class type to return;
	 * @param headers    returned from URL
	 * @param key        to look for
	 * @param defaultVal value to return if key not found.
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private <T> T getFirstHeader(Class<T> asClass, Map<String, List<String>> headers, String key, Object defaultVal) {
		List<String> lms = headers.get(key);
		if (lms != null && !lms.isEmpty()) {
			try {
				if (Date.class.isAssignableFrom(asClass))
					return (T) parseDate(lms.get(0));

				if (Integer.class.isAssignableFrom(asClass))
					return (T) new Integer(lms.get(0));

				if (String.class.isAssignableFrom(asClass))
					return (T) lms.get(0);

			} catch (Exception e) {
				log.error("Failed to parse " + key + ":" + lms.get(0));
			}
		}

		return (T) defaultVal;
	}

	/**
	 * Get Last-Modified and Content-Length from headers. Prints headers at info log
	 * level
	 */
	private void checkHeaders(HttpURLConnection con) throws ParseException {
		conHeaders = con.getHeaderFields();
		for (String key : conHeaders.keySet()) {
			log.debug(key + ":" + conHeaders.get(key));
		}
		modDate = getFirstHeader(Date.class, conHeaders, "Last-Modified", modDate);
		len = getFirstHeader(Long.class, conHeaders, "Content-Length", len);
		contentType = getFirstHeader(String.class, conHeaders, "Content-Type", contentType);

	}

	/**
	 * Read the contents of the url into a String
	 * 
	 * @param con       open connection
	 * @param includeNL if true includes new lines, false strips them
	 * @return contents of page
	 */
	private String getUrlContentAsString(HttpURLConnection con, boolean includeNL) {

		StringBuilder sb = new StringBuilder();
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()))) {

			String line = null;
			while ((line = reader.readLine()) != null) {
				sb.append(line);
				if (includeNL) {
					sb.append("\n");
				}
			}
		} catch (Exception e) {
			log.error("Failed reading url", e);
		} finally {

		}

		return sb.toString();
	}

	private void mapDevices(JSONArray resp) {
		deviceMap = new HashMap<String, String>();
		for (int i = 0; i < resp.size(); i++) {
			JSONObject jo = (JSONObject) resp.get(i);
			deviceMap.put(jo.getString("deviceName"), jo.getString("cid"));
		}
	}

	/**
	 * Get cid for deviceName
	 * 
	 * @param deviceName
	 * @return the cid for the device
	 * @throws BAD_PARAM if device is unknown
	 */
	protected String getCid(String deviceName) {
		loadDeviceMap(deviceName);
		String cid = deviceMap.get(deviceName);
		if (StringUtils.isBlank(cid)) {
			throw new BAD_PARAM(deviceName + " is not a known device name. Should be one of:" + deviceMap.keySet());
		}
		return cid;
	}

	/**
	 * load device name to cid map.
	 * 
	 * @param deviceName
	 */
	protected void loadDeviceMap(String deviceName) {
		JSONArray resp = null;
		Path p = Paths.get(DEVICE_JSON);
		if (Files.exists(p)) {
			try {
				String content = new String(Files.readAllBytes(p));
				resp = JSONArray.fromObject(content);
				mapDevices(resp);
			} catch (IOException e) {
				log.error("Saving devices.json failed", e);
			}
		}

		// if cache missing or we are looking for a key and not in the cache then reload
		// from server.
		if (resp == null || (deviceName != null && !deviceMap.containsKey(deviceName))) {
			resp = updateDeviceInfo();
			mapDevices(resp);
		}

		if (log.isDebugEnabled()) {
			log.debug("deviceMap:" + deviceMap);
		}
	}

	/**
	 * Common PUT method used by sendOn() and sendOff(). Only public in cause useful
	 * later.
	 * 
	 * @param params
	 * @param cid
	 * @param status
	 * @return response String
	 */
	public String putDeviceStatus(JSONObject params, String cid, String status) {
		// requests.put(BASE_URL + '/v1/wifi-switch-1.3/' + id + '/status/on',
		// verify=False, data={}, headers=self.get_headers())
		String result = null;
		try {
			URL url = new URL(BASE_URL + COMMAND_SUB_URL + cid + "/status/" + status);

			result = sendReq(params, url, "PUT");
		} catch (Exception e) {
			log.error("putDeviceStatus failed", e);
		}

		log.debug("putDeviceStatus response:" + result);

		return result;
	}

	/**
	 * Get the basic config info of all the devices on the server and cache it to
	 * DEVICE_JSON
	 * 
	 * @return JSONArray of device details
	 */
	public JSONArray updateDeviceInfo() {
		// self._devices = requests.get(BASE_URL + '/vold/user/devices', verify=False,
		// headers=self.get_headers()).json()
		JSONArray resp = null;
		try {
			URL url = new URL(BASE_URL + GETDEVICES_SUB_URL);
			String result = sendReq(null, url, "GET");
			resp = JSONArray.fromObject(result);
			try (FileWriter writer = new FileWriter(DEVICE_JSON, false)) {
				writer.write(result);
			} catch (IOException e) {
				log.error("Saving devices.json failed", e);
			}

			log.debug("getDevices response:" + resp);
		} catch (Exception e) {
			log.error("getDevices failed", e);
		}

		return resp;
	}

	/**
	 * Send request to cloud.
	 * 
	 * @param parms   JSONObject to be sent in PUT or POST. Note currently only used
	 *                for login POST.
	 * @param url
	 * @param reqType "GET", "PUT" or "POST"
	 * @return the response String from server. Could be empty or JSON as String.
	 * @throws IOException
	 * @throws KeyManagementException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws ParseException
	 */
	public String sendReq(JSONObject parms, URL url, String reqType) throws IOException, KeyManagementException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException, ParseException {
		String result = null;

		if (parms == null && StringUtils.isBlank(tk)) {
			if (!jsonLogin()) {
				throw new IOException("Login failed");
			}
		}
		initSSL(url);

		log.info("Connecting to:" + url);
		HttpURLConnection.setFollowRedirects(followRedirects);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setConnectTimeout(timeout);
		if (con instanceof HttpsURLConnection) {
			((HttpsURLConnection) con).setHostnameVerifier(HttpsVerifier.getInstance());
			((HttpsURLConnection) con).setSSLSocketFactory(sslSocketFactory);
		}
		if (StringUtils.isNotBlank(tk))
			con.setRequestProperty("tk", tk);
		if (StringUtils.isNotBlank(accountID))
			con.setRequestProperty("accountID", accountID);
		con.setRequestMethod(reqType);
		byte[] postData = null;
		if (parms != null) {
			postData = parms.toString().getBytes();
			int postDataLength = postData.length;
			con.setDoOutput(true);
			con.setInstanceFollowRedirects(false);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Length", Integer.toString(postDataLength));
			con.setUseCaches(false);
			try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
				wr.write(postData);
			}
		} else {
			con.setRequestProperty("Accept", "text/html, application/xhtml+xml, application/xml; q=0.9, */*; q=0.8");
			con.setRequestProperty("User-Agent", userAgentString);
			con.setRequestProperty("Accept-Language", "en-US, en; q=0.5");
		}

		try {
			if (postData != null)
				log.debug("postData:" + new String(postData));
			checkHeaders(con);
		} catch (ParseException e) {
			log.warn("Could not display debug info for:" + con);
		}

		try {
			setRespCode(con.getResponseCode());
		} catch (Exception e) {
			tryTlsPlusCertInstall(con, url, e);
		}
		// if connects OK do the read just to be sure
		if (respCode == HttpURLConnection.HTTP_OK || ignoreRespCode) {
			result = getUrlContentAsString(con, true);
		} else if (respCode == HttpURLConnection.HTTP_MOVED_TEMP || ignoreRespCode) {
			result = getUrlContentAsString(con, true);
		} else if (respCode == HttpURLConnection.HTTP_FORBIDDEN || ignoreRespCode) {
			StringBuilder sb = new StringBuilder();
			for (String key : conHeaders.keySet()) {
				sb.append(key).append(":").append(conHeaders.get(key)).append('\n');
			}
			result = sb.toString();

		} else {
			log.error("Failed:" + respCode + ": " + con.getResponseMessage());
		}
		log.debug("sendReq response:" + result);

		return result;
	}

	private static class SavingTrustManager implements X509TrustManager {

		private final X509TrustManager tm;
		private X509Certificate[] chain;

		SavingTrustManager(X509TrustManager tm) {
			this.tm = tm;
		}

		public X509Certificate[] getAcceptedIssuers() {
			throw new UnsupportedOperationException();
		}

		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			throw new UnsupportedOperationException();
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			this.chain = chain;
			tm.checkServerTrusted(chain, authType);
		}
	}

	/**
	 * Send "on" to device with name deviceName
	 * 
	 * @param deviceName
	 * @return blank or error response string
	 */
	public String sendOn(String deviceName) {
		// requests.put(BASE_URL + '/v1/wifi-switch-1.3/' + id + '/status/on',
		// verify=False, data={}, headers=self.get_headers())
		String cid = getCid(deviceName);
		return putDeviceStatus(null, cid, "on");
	}

	/**
	 * Send "off" to device with name deviceName
	 * 
	 * @param deviceName
	 * @return blank or error response string
	 */
	public String sendOff(String deviceName) {
		// requests.put(BASE_URL + '/v1/wifi-switch-1.3/' + id + '/status/off',
		// verify=False, data={}, headers=self.get_headers())
		String cid = getCid(deviceName);
		return putDeviceStatus(null, cid, "off");

	}

	/**
	 * Get details of device by name
	 * 
	 * @param deviceName
	 * @return JSONObject like
	 *         {"deviceStatus":"off","deviceImg":"https://image.vesync.com/defaultImages/ESW01_USA_Series/icon_7a_wifi_outlet_160.png","energy":0.0,"activeTime":26936166,"power":"0:0","voltage":"0:0"}
	 */
	public JSONObject getDetails(String deviceName) {
		// self._details = requests.get(BASE_URL + '/v1/device/' + id + '/detail',
		// headers=self.get_headers()).json()
		String cid = getCid(deviceName);
		JSONObject resp = null;
		try {
			URL url = new URL(BASE_URL + DEVICE_SUB_URL + cid + "/detail");
			String result = sendReq(null, url, "GET");
			resp = JSONObject.fromObject(result);
			log.debug("getDetails response:" + resp);
		} catch (Exception e) {
			log.error("getDetails failed", e);
		}

		return resp;
	}

	/**
	 * Get energy data for device named deviceName for period
	 * 
	 * @param deviceName
	 * @param period     one of "week", "month" or "year"
	 * @return JSONObject like
	 *         {"energyConsumptionOfToday":0.0089,"costPerKWH":0,"maxEnergy":0.0358,"totalEnergy":0.2003,"currency":"USD","data":[0.0358,0.0284,0.0322,0.0312,0.0309,0.0325,0.0089]}
	 */
	public JSONObject getEnergy(String deviceName, String period) {
		// TODO:
		// self._energy = requests.get(BASE_URL + '/v1/device/' + id + '/energy/month',
		// headers=self.get_headers()).json()
		String cid = getCid(deviceName);
		JSONObject resp = null;
		try {
			URL url = new URL(BASE_URL + DEVICE_SUB_URL + cid + "/energy/" + period);
			String result = sendReq(null, url, "GET");
			resp = JSONObject.fromObject(result);

			log.debug("getEnergy response:" + resp);
		} catch (Exception e) {
			log.error("getEnergy failed", e);
		}

		return resp;
	}

	public void usage() {
		System.err.println("USAGE:" + getClass().getSimpleName() + " [deviceName] [option] [-l login] [-p password]");
		System.err.println("with no arguments reads device info from site and saves to " + DEVICE_JSON);
		System.err.println("deviceName is the name from the app");
		System.err.println("option is one of");
		System.err.println("-h print this help");
		System.err.println("-l login");
		System.err.println("-p password");
		System.err.println("if -l or -p is used they override and replace what is in the Etekcity.properties file");
		System.err.println("-on send turn on");
		System.err.println("-off send turn of");
		System.err.println("-reset send turn off, pause " + pauseSecs + " seconds, then send turn on");
		System.exit(1);
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Vesync v = new Vesync();
		try {
			String deviceName = null;
			String action = "";
			boolean updateProps = false;
			if (args != null && args.length > 0) {
				for (int i = 0; i < args.length; i++) {
					if (args[i].startsWith("-")) {
						switch (args[i]) {
						case "-h":
							v.usage();
							break;

						case "-l":
							v.setLogin(args[++i]);
							updateProps = true;
							break;

						case "-p":
							MessageDigest md = MessageDigest.getInstance("MD5");
							byte[] arr = args[++i].getBytes();
							arr = md.digest(arr);
							StringBuilder sb = new StringBuilder();
							for (byte b : arr) {
								sb.append(String.format("%02x", b));
							}
							v.setPassword(sb.toString());
							updateProps = true;
							break;

						case "-on":
							action = args[i];
							break;

						case "-off":
							v.usage();
							break;

						case "-reset":
							action = args[i];
							break;

						default:
							System.err.println(args[i] + " is invalid");
							v.usage();
							break;
						}

					} else {
						deviceName = args[i];
					}
				}
			}

			if (updateProps) {
				StringBuilder sb = new StringBuilder("## Talk to Etekcity plugs via cloud service");
				sb.append(System.lineSeparator()).append("##username for Vesync (etekcity)");
				sb.append(System.lineSeparator()).append("login=").append(v.getLogin());
				sb.append(System.lineSeparator()).append("##MD5 encoded password for Vesync (etekcity)");
				sb.append(System.lineSeparator()).append("password=").append(v.getPassword());
				try (FileWriter writer = new FileWriter(BUNDLENAME + ".properties", false)) {
					writer.write(sb.toString());
				} catch (IOException e) {
					System.err.println("Saving " + BUNDLENAME + ".properties failed");
					v.usage();
				}
				File f = new File(BUNDLENAME + ".properties");
				System.out.println("login and encrypted password saved to:" + f.getAbsolutePath());
			}
			switch (action) {
			case "-on":
				v.sendOn(deviceName);
				break;

			case "-off":
				v.sendOff(deviceName);
				break;

			case "-reset":
				v.sendOff(deviceName);
				try {
					Thread.sleep(v.getPauseSecs() * 1000);
				} catch (InterruptedException e) {
					// to keep compiler happy
					e.printStackTrace();
				}
				v.sendOn(deviceName);
				break;

			default:
				v.loadDeviceMap(deviceName);
				break;
			}
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Failed to encode password");
			v.usage();
		}
	}

	/**
	 * @return the login
	 */
	public String getLogin() {
		return login;
	}

	/**
	 * @return the password
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * @return the pauseSecs
	 */
	public int getPauseSecs() {
		return pauseSecs;
	}

	/**
	 * @param pauseSecs the pauseSecs to set
	 */
	public void setPauseSecs(int pauseSecs) {
		this.pauseSecs = pauseSecs;
	}

	/**
	 * @return the timeout
	 */
	public int getTimeout() {
		return timeout;
	}

	/**
	 * @param timeout the timeout to set
	 */
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	/**
	 * @return the deviceMap
	 */
	public Map<String, String> getDeviceMap() {
		return deviceMap;
	}

	/**
	 * @return the respCode
	 */
	public int getRespCode() {
		return respCode;
	}

	/**
	 * @return the respHeaders
	 */
	public Header[] getRespHeaders() {
		return respHeaders;
	}
}
