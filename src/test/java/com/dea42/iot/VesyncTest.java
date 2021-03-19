/**
 * 
 */
package com.dea42.iot;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.util.ResourceBundle;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * @author avata
 *
 */
public class VesyncTest {

	public static final String BAD_DEVICE_NAME = "BAD DEVICE NAME";

	// name of a device you have to test with
	public String testDeviceName;

	@Before
	public void setUp() throws Exception {
		ResourceBundle bundle = ResourceBundle.getBundle(Vesync.BUNDLENAME + "Test");
		testDeviceName = bundle.getString("testDeviceName");
	}

	/**
	 * Test method for {@link com.dea42.iot.Vesync#jsonLogin()}.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testJsonLogin() throws Exception {
		Vesync v = new Vesync();
		assertTrue("test login", v.jsonLogin());
	}

	/**
	 * Test method for {@link com.dea42.iot.Vesync#loadDeviceMap(java.lang.String)}.
	 */
	@Test
	public void testLoadDeviceMap() {
		File f = new File(Vesync.DEVICE_JSON);
		assertTrue("failed to delete " + Vesync.DEVICE_JSON, f.delete());
		Vesync v = new Vesync();
		v.loadDeviceMap(null);
		assertFalse("deviceMap empty", v.getDeviceMap().isEmpty());
		f = new File(Vesync.DEVICE_JSON);
		assertTrue(f.getAbsolutePath() + " was not created", f.exists());
		long lastMod = f.lastModified();

		// test loads from cache not cloud
		v = new Vesync();
		v.loadDeviceMap(null);
		f = new File(Vesync.DEVICE_JSON);
		assertTrue(f.getAbsolutePath() + " was modified and should not have been", lastMod == f.lastModified());
		assertFalse("deviceMap empty", v.getDeviceMap().isEmpty());

		// test that we reload from cloud when device name not in cache
		v = new Vesync();
		v.loadDeviceMap(BAD_DEVICE_NAME);
		f = new File(Vesync.DEVICE_JSON);
		assertTrue(f.getAbsolutePath() + " was not modified and should have been", lastMod != f.lastModified());
		assertFalse("deviceMap empty", v.getDeviceMap().isEmpty());
	}

	/**
	 * Test method for {@link com.dea42.iot.Vesync#getDetails(java.lang.String)}.
	 */
	@Test
	public void testGetDetails() {
		Vesync v = new Vesync();
		JSONObject ja = v.getDetails(testDeviceName);
		assertFalse("Empty object returned", ja.isEmpty());
		assertNotNull("deviceStatus", ja.get("deviceStatus"));
		assertNotNull("deviceImg", ja.get("deviceImg"));
		assertNotNull("energy", ja.get("energy"));
		assertNotNull("activeTime", ja.get("activeTime"));
		assertNotNull("power", ja.get("power"));
		assertNotNull("voltage", ja.get("voltage"));
	}

	/**
	 * Test method for
	 * {@link com.dea42.iot.Vesync#getEnergy(java.lang.String,java.lang.String)}.
	 */
	@Test
	public void testGetEnergy() {
		Vesync v = new Vesync();
		String[] periods = { "week", "month", "year" };
		for (int i = 0; i < 3; i++) {
			JSONObject ja = v.getEnergy(testDeviceName, periods[i]);
			assertFalse("Empty object returned", ja.isEmpty());
			assertNotNull("energyConsumptionOfToday", ja.get("energyConsumptionOfToday"));
			assertNotNull("costPerKWH", ja.get("costPerKWH"));
			assertNotNull("maxEnergy", ja.get("maxEnergy"));
			assertNotNull("totalEnergy", ja.get("totalEnergy"));
			assertNotNull("currency", ja.get("currency"));
			assertNotNull("data", ja.get("data"));
		}

		JSONObject ja = v.getEnergy(testDeviceName, "");
		assertFalse("Error response expected", ja.isEmpty());
		assertNotNull("error", ja.get("error"));
	}

	/**
	 * Test method for {@link com.dea42.iot.Vesync#updateDeviceInfo()}.
	 */
	@Test
	public void testUpdateDeviceInfo() {
		Vesync v = new Vesync();
		JSONArray ja = v.updateDeviceInfo();
		assertFalse("Empty array returned", ja.isEmpty());
		File f = new File(Vesync.DEVICE_JSON);
		assertTrue(f.getAbsolutePath() + " was not created", f.exists());
	}

	/**
	 * Test method for {@link com.dea42.iot.Vesync#getCid(java.lang.String)}.
	 */
	@Test
	public void testGetCid() {
		Vesync v = new Vesync();
		String resp = v.getCid(testDeviceName);
		assertTrue("Failed to get cid of known name", StringUtils.isNotBlank(resp));
	}

	/**
	 * Test method for {@link com.dea42.iot.Vesync#getCid(java.lang.String)}.
	 */
	@Test
	public void testGetCidBad() {
		Vesync v = new Vesync();
		try {
			v.getCid(BAD_DEVICE_NAME);
			fail("Expected exception");
		} catch (Exception e) {
			// expected
		}
	}

	/**
	 * Test method for {@link com.dea42.iot.Vesync#sendOn(java.lang.String)}.
	 */
	@Test
	public void testSendOn() {
		Vesync v = new Vesync();
		String resp = v.sendOn(testDeviceName);
		assertTrue("Got error", StringUtils.isBlank(resp));
		JSONObject ja = v.getDetails(testDeviceName);
		assertFalse("Empty object returned", ja.isEmpty());
		assertTrue("Status incorrect", ja.get("deviceStatus").toString().equals("on"));
	}

	/**
	 * Test method for {@link com.dea42.iot.Vesync#sendOff(java.lang.String)}.
	 */
	@Test
	public void testSendOff() {
		Vesync v = new Vesync();
		String resp = v.sendOff(testDeviceName);
		assertTrue("Got error", StringUtils.isBlank(resp));
		JSONObject ja = v.getDetails(testDeviceName);
		assertFalse("Empty object returned", ja.isEmpty());
		assertTrue("Status incorrect", ja.get("deviceStatus").toString().equals("off"));
	}

}
