/************************************************************************
* Narseo Vallina-Rodriguez. University of Cambridge. 2013				*
* narseo@gmail.com                                                      *
*************************************************************************/

package cl.narseo.rilLogger;

import android.app.Service;
import android.os.AsyncResult;
import android.os.Bundle;
import android.os.Handler;
import android.os.Binder;
import android.os.IBinder;
import android.content.Intent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Message;
import android.text.TextUtils;
import android.util.Log;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import com.android.internal.telephony.Phone;
import com.android.internal.telephony.PhoneFactory;
import android.telephony.TelephonyManager;

import java.util.Arrays;
import java.lang.String;
import java.io.*;
import java.net.*;

public class RILMonitorService extends Service {

    private static final String TAG = "SPC";

    private static String PREV_RIL_STATE = "-1";
    private static String PREV_REPORT = "-1";
    private static boolean PREV_SCREEN_STATE = false; 

  	private ScreenReceiver mScreenReceiver = null;
  	private static boolean radioIsOff = false;
  	private static String PREV_RRC = "INITIAL";

    public static final String EXTRA_SECRET_CODE = "secret_code";

    private static final int ID_SERVICE_MODE_REFRESH = 1001;
    private static final int ID_SERVICE_MODE_REQUEST = 1008;
    private static final int ID_SERVICE_MODE_END = 1009;

    private static final int DIALOG_INPUT = 0;

    private static final int CHARS_PER_LINE = 34;
    private static final int LINES = 11;

    private int mCurrentSvcMode;
    private int mCurrentModeType;
    private boolean DEBUG = false;	
	
	//Used to get type of network connectivity (GSM/3GPP Standard)
	private TelephonyManager mTelephonyManager;


    // Disable back when initialized with certain commands due to crash
    private boolean mAllowBack;
    private boolean mFirstRun = true;
    private String mFirstPageHead;

  	private final IBinder mBinder = new MyBinder();

	// Used to communicate with the logger
	private DatagramSocket loggerClientSocket;
	private byte[] loggerBuffer = new byte[1024];
    private InetAddress loggerIPAddress;
	private static final int LOGGER_UDP_PORT = 9930;


    private Phone mPhone;
    
  	/*
  	* Broadcast receiver for a 1sec granularity info about the state of the screen
  	* 
  	* Instead of having events, we will consider that with the RNC states
  	* and will be sent together to the logger
  	*/
  	public class ScreenReceiver extends BroadcastReceiver { 

		public boolean wasScreenOn = true;

		@Override
		public void onReceive(Context context, Intent intent) {
			if (intent.getAction().equals(Intent.ACTION_SCREEN_OFF)) {
				wasScreenOn = false;
			} else if (intent.getAction().equals(Intent.ACTION_SCREEN_ON)) {
				wasScreenOn = true;
			}
		}

		public int getScreenState(){
			if (wasScreenOn){
				return 1;
			}
			return 0;
		}
	}

  /*
	* Sends UDP socket to logger server on a given port defined by LOGGER_UDP_PORT
	*/
	private void rncLogger (String data){
		try{		
			loggerBuffer = data.getBytes();
		
			DatagramPacket sendPacket = 
				new DatagramPacket(loggerBuffer, 
				loggerBuffer.length, 
				loggerIPAddress, 
				LOGGER_UDP_PORT);
    	  	loggerClientSocket.send(sendPacket);
		}
		catch(Exception e){
			Log.e(TAG, "Error sending log event: "+data);
			Log.e(TAG, e.getMessage());
		}
	}

    private Handler mHandler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
			if (DEBUG) Log.i(TAG, "HANDLE MESSAGE: "+msg.what);
			
			int modeType = OemCommands.OEM_SM_TYPE_MONITOR;
	 		int subType = OemCommands.OEM_SM_TYPE_SUB_ENTER;
        	byte[] dataToSend = OemCommands.getEnterServiceModeData(modeType, subType, OemCommands.OEM_SM_ACTION);

            switch(msg.what) {
				case ID_SERVICE_MODE_REFRESH:
					    Log.i(TAG, "Type: ID_SERVICE_MODE_REFRESH. Maybe no network. Wait until there's network");
			        mCurrentSvcMode = OemCommands.OEM_SM_ENTER_MODE_MESSAGE;
        			mCurrentModeType = modeType;
					if (isAirplaneModeOn()){
						  Log.i(TAG, "*****AIRPLANE MODE*****\tDelayed Message");
						  mHandler.sendEmptyMessageDelayed(ID_SERVICE_MODE_REFRESH, 30000);
					}								
					else{	
	        			sendRequest(dataToSend, ID_SERVICE_MODE_REQUEST);
					}
					break;
            	case ID_SERVICE_MODE_REQUEST:
					try{
						if (DEBUG) Log.i(TAG, "Type: ID_SERVICE_MODE_REQUEST");
	                	AsyncResult result = (AsyncResult)msg.obj;
	                	if (result.exception != null) {
	                    		Log.e(TAG, "Exception occurred and caught" + result.exception);
					                Log.i(TAG, "*****Delayed Message");
	                        mHandler.sendEmptyMessageDelayed(ID_SERVICE_MODE_REFRESH, 30000);		
					                break;
	                    		//return;
	                	}
	                	if (result.result == null) {
	                    	if (DEBUG) Log.v(TAG, "No need to refresh.");
	                    	return;
	                	}
	                	byte[] aob = (byte[])result.result;
	
	                	if (aob.length == 0) {
	                    	if (DEBUG) Log.v(TAG, "Length = 0");
	                    	return;
	                	}
	
						long timestamp = SystemClock.elapsedRealtime();
	                	int lines = aob.length / CHARS_PER_LINE;
	                	if     (lines > LINES) {
	                   		Log.e(TAG, "Datasize " + aob.length + " larger than expected");
	                    		return;
	                	}
	
						//Send the logger the data: RNC State, HSPA Channels, RSCP data
						String RRC = "-1"; //Default in case there's an error
						String HSPA = "-1";
						String RSCP = "-1,-1,-1";
						//Kind of slow but that's all that can be done
	                	for (int i = 0; i < lines; i++) {
	                    	StringBuilder strb = new StringBuilder(CHARS_PER_LINE);
	                    	for (int j = 2; i < CHARS_PER_LINE; j++) {
	                        	int pos = i * CHARS_PER_LINE + j;
	                        	if (pos >= aob.length) {
	                            		Log.e(TAG, "Unexpected EOF");
	                            		break;
	                        	}
	                        	if (aob[pos] == 0) {
	                            		break;
	                        	}
	                        	strb.append((char)aob[pos]);
	                    	}
	
							try{
								String currentLine = strb.toString();
								if (currentLine.contains("RRC")){
									String []  items = currentLine.split(": ");
									RRC = items[1];
								}
								else if(strb.toString().contains("HSPA")){
									String []  items = currentLine.split(": ");
									HSPA = items[1];
									if (DEBUG) Log.i(TAG, "HSPA,"+HSPA);							
								}
								else if (strb.toString().contains("RSCP")){
									String []  items = currentLine.split(":");
									RSCP = items[1].substring(0,3)+","+
										items[2].substring(0,3)+","+
										items[3].substring(0,2);
								}
							}
							catch (Exception e){
								Log.e(TAG, "Error parsing RNC states: "+e.getMessage());
							}
		             	}
						//Radio: RRC State, HSPA Channels, Current RSCP, Average RSCP, ECIO
						if (RRC.equals("-1") && RRC.equals(PREV_RRC)){
							radioIsOff = true;
						}	
						else{
							//Only print positive events. If two RRC values are "-1"
							//only the first one is printed,
							radioIsOff = false;
				          	String currentReport = "RADIO,"+
				          		mScreenReceiver.getScreenState()+","+
				          		mTelephonyManager.getNetworkType()+","+
				          		RRC+","+
				          		HSPA+","+
				          		RSCP+"\n";
				          	if (currentReport.equals(PREV_REPORT)==false){
				            	//Only report radio event if the current report differs from the
				            	//prev one to reduce writing too much on sd card
							  	rncLogger(currentReport);
				        	    PREV_REPORT = currentReport;
				          	}
						}
						PREV_RRC = RRC;
	
	                    //mHandler.sendEmptyMessageDelayed(ID_SERVICE_MODE_REFRESH, 200);					
				        mCurrentSvcMode = OemCommands.OEM_SM_ENTER_MODE_MESSAGE;
	        			mCurrentModeType = modeType;	
						if (isAirplaneModeOn()){
							//Airplane mode is complicated. Better solution needed.
							//If polled too often, it hungs the RIL daemon
							//and the device can have trouble trying to reconnect.
							//This prevents the logger to poll the radio that often
							//if the user has turn Airplane Mode On. 
							Log.i(TAG, "*****AIRPLANE MODE*****\tDelayed Message");
							mHandler.sendEmptyMessageDelayed(ID_SERVICE_MODE_REFRESH, 30000);
						}								
						else{	
		        			sendRequest(dataToSend, ID_SERVICE_MODE_REQUEST);
						}
	                }
					catch(Exception e){
						Log.e(TAG, e.getMessage());
						Log.i(TAG, "*****ERROR*****\tDelayed Message");
	                    mHandler.sendEmptyMessageDelayed(ID_SERVICE_MODE_REFRESH, 10000);
					}
					break;
            	case ID_SERVICE_MODE_END:
					if (DEBUG) Log.i(TAG, "Type: ID_SERVICE_MODE_END");
                	if (DEBUG) Log.v(TAG, "Service Mode End");
                		break;
            }//switch
        }
	};


	/**
	* Gets the state of Airplane Mode.Used to avoid polling the system if it's OFF 	
	* Otherwise, it kills the thread and it's not recovered unless the device
	* is rebooted
	* 
	* @param context
	* @return true if enabled.
	*/
	private boolean isAirplaneModeOn() {
	   return Settings.System.getInt(this.getContentResolver(),
		       Settings.System.AIRPLANE_MODE_ON, 0) != 0;
	}

	/**
	*	Binds the background service
	*/
	public IBinder onBind(Intent arg0) {
		if (DEBUG) Log.i(TAG, "onBind");
		return mBinder;
  	}

	public class MyBinder extends Binder {
		RILMonitorService getService() {
			if (DEBUG) Log.i(TAG, "MyBinder.getService()");
		  	return RILMonitorService.this;
		}
	}


	public void initialize(){
		if (DEBUG) Log.i(TAG, "initialize(). Nothing to do");
	}

    /**
     * Required for service implementation.
	 * Starts the monitoring 
     */
    @Override
    public void onStart(Intent intent, int startId) {
		if (DEBUG) Log.i(TAG, "onStart()");
        int modeType = OemCommands.OEM_SM_TYPE_MONITOR;
        int subType = OemCommands.OEM_SM_TYPE_SUB_ENTER;		
        enterServiceMode(modeType, subType);
    }

	public void onCreate(){
		if (DEBUG) Log.i(TAG, "OnCreate(). Attempting to get default phone");
		//PhoneFactory.makeDefaultPhone(this);
        if (mPhone==null) {
			Log.i(TAG, "Phone is not created. Creating a new one");
			mPhone = PhoneFactory.getDefaultPhone();
		}
		Log.i(TAG, "Getting telephony manager to get type of net");
		mTelephonyManager = (TelephonyManager)this.getSystemService(Context.TELEPHONY_SERVICE);

		try{
			loggerClientSocket = new DatagramSocket();
    		loggerIPAddress = InetAddress.getByName("localhost");
		}
		catch(Exception e){
			Log.e(TAG, "ERROR Creating socket for logging: "+e.getMessage());
		}
		//Register intent filter to get screen events
		mScreenReceiver = new ScreenReceiver();
		IntentFilter filter = new IntentFilter(Intent.ACTION_SCREEN_ON);
		filter.addAction(Intent.ACTION_SCREEN_OFF);
		registerReceiver(mScreenReceiver, filter);
	}

	/*
	* Calls the Ril
	*/
    private void enterServiceMode(int modeType, int subType) {
	if(DEBUG) Log.i(TAG, "Call RIL. ModeType: "+modeType+" / subType: "+subType);
        mCurrentSvcMode = OemCommands.OEM_SM_ENTER_MODE_MESSAGE;
        mCurrentModeType = modeType;
        byte[] data = OemCommands.getEnterServiceModeData(modeType, subType, OemCommands.OEM_SM_ACTION);
        sendRequest(data, ID_SERVICE_MODE_REQUEST);
    }

    private void sendString(String str) {
	if (DEBUG) Log.i(TAG, "sendString: "+str);
        for (char chr : str.toCharArray()) {
            sendChar(chr);
        }
        sendChar((char) 83); // End
    }
    
    private void sendChar(char chr) {
	if (DEBUG) Log.i(TAG, "sendChar: "+chr);
        mCurrentSvcMode = OemCommands.OEM_SM_PROCESS_KEY_MESSAGE;
        mHandler.removeMessages(ID_SERVICE_MODE_REFRESH);
        if (chr >= 'a' && chr <= 'f') {
            chr = Character.toUpperCase(chr);
        } else if (chr == '-') {
            chr = '*';
        }
        byte[] data = OemCommands.getPressKeyData(chr, OemCommands.OEM_SM_ACTION);
        sendRequest(data, ID_SERVICE_MODE_REQUEST);
    }

    private void sendRequest(byte[] data, int id) {
	String dataToSend = new String(data);
	if (DEBUG) Log.i(TAG, "sendRequest. ID:"+id+"/ data: "+dataToSend+"/ DATA Format2: "+Arrays.toString(data));

        Message msg = mHandler.obtainMessage(id);
        mPhone.invokeOemRilRequestRaw(data, msg);
    }

    private void sendRequest(byte[] data, int id) {
	String dataToSend = new String(data);
	if (DEBUG) 
          Log.i(TAG, "sendRequest. ID:"+id+"/ data: "+dataToSend+"/ DATA Format2: "+Arrays.toString(data));
		
        Message msg = mHandler.obtainMessage(id);
        mPhone.invokeOemRilRequestRaw(data, msg);
    }

}
