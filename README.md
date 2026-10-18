# TAPO-windows-audio-control
a native windows tray that turns your sound system on or off when audio plays


I had a problem where TPLink makes hardware but not any useful windows software or even a useful app and I didn't want to deploy an entire home assistant VM to control it. My sound system includes a few amplifiers including power hungry Class A amplifiers that consume a lot of power to play silence and have annoyingly bright power indicator LEDs. previously I had to load up a clunky TAPO app, navigate to an option, tap the broken UI button a few times that would often incorrectly report that the power had been toggled in the UI and then I could turn the speakers on and off. Due to this time consuming task I developed this tray app to automatically or manually turn the relay on or off. you must be on the same subnet for this to work. This program is very light at 2.8MB of RAM usage because it is a native windows application with no virtualized python or JAVA RTE nonsense.


on first run it will prompt you for your TAPO credentials. edit the auto power-down delay to suit your needs. set the IP of the TAPO device you want to control. I believe there is a TPLink limitation that your PC must be on the same subnet as your PC for this to work.
