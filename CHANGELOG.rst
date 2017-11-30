0.8.2a
----------
* fixing bug reported by @garanews. When the user is using BRO splitted files ManaTI was not detecting correctly the
  headers.
* Fixing a bug when the user is creating a new analysis session, it upload a weblog file and after that, upload
  another one, the table was not created properly and a popup was displayed showing some errors with the columns.
* minor changes

0.8.1.551a
----------
* fixing bug deleting an analysis session. The response page was wrong redirected
* fixing bug reported in the moment to run WSD module
* minor others changes

0.8.0.537a
----------
* Adding threshold slider bar in the WHOIS DISTANCE modal 😃
* Adding the possibility to inspect the WSD of the **seed** domain with the rest of the domains in modal. So, now the user can see the used features, the distance between each feature, the measured WHOIS information and the WHOIS distance (total) 😃
* Adding configurations to use Docker Composer in ManaTI 😍  . Read README.md file for more information.
* Fixed bug registering or checking for changes in External Modules. New command added **check_external_modules**. Read README.md file for more information.
* Adding UserProfile page and encrypted fields. User Profile (model and page) has some minor bugs, we will fix it soon. Also, the option to generate **fieldkeys** will be added.
* Adding 'fancy' error pages as templates. Minor moving of static directory. For development use **/static1**. When ManaTI is deployed, all the web assets (js/css/images/fonts/etc) will be compressed in **/static**.
* LICENSE file moved to **/docs**

0.8.0.1a
--------
* Adding redis server to background task
* Adding more hotkeys and navigation keys
* Minor UI changes
* improve the sync process of weblogs
* add IOC model and functions
* adding coments per weblogs
* Improvements in the algorithm to relate domains using their WHOIS information
* fixing bugs

0.7.1
-----
* Stable version of ManaTI