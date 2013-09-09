/* (C) 2012 Pragmatic Software
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/
 */

package com.googlecode.networklog;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.preference.PreferenceManager;
import android.content.SharedPreferences;
import android.util.Log;

public class PackageMonitorReceiver extends BroadcastReceiver {
  @Override
    public void onReceive(Context context, Intent intent) {
      Log.d("SPC_NetworkLog", "PackageMonitorReceiver-----> Received broadcast: " + intent.getAction());
      ApplicationsTracker.getInstalledApps(context, null);
    }
}
