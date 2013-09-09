/************************************************************************
* Narseo Vallina-Rodriguez. University of Cambridge. 2013				*
* narseo@gmail.com                                                      *
*************************************************************************/


package cl.narseo.rilLogger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/*
* Starts the background service when the booting finishes with secret code OO11
*/
public class SecretBroadcastReceiver extends BroadcastReceiver {

	private static final String TAG = "SPC_SecretBroadcastReceiver";
    @Override
    public void onReceive(Context context, Intent intent) {
		String code = "0011";
		Intent i = new Intent(context, SamsungServiceModeActivity.class);
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        i.putExtra(SamsungServiceModeActivity.EXTRA_SECRET_CODE, code);

		Log.i(TAG,"StartService: "+i.toString()+" with code "+code);
		context.startService(i);
    }
}
