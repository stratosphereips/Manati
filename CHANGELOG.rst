----------
* Adding settings for heroku deployment
* Minor change in config/urls.py. Removing urls that we are not using and adding a routing http://localhost:8000/ or https://<YOUR-DOMAIN>/
* Fixing bug with the user logout the page, it was wrong redirected. Now it is going to the login page.
* Fixing bugs related with the new structured files
* Adding library **bat** for processing BRO files. For now it is in the requirements/test.txt, for testing env. We will see if we will need it
in another place of the system.
* Adding testing settings and one unitest for the AnalysisSession model. Now, there are two method,
one for testing the creation process of one analysis session with cisco type files and another one for  BRO http.log file case.
For running the test is just necessary to use the console and execute **pytest**. The pytest.ini is already configured
* Adding example (docs/example_weblogs) of BRO file and Apache file
* Adding badges in README file

0.9.2a
----------
* Adding function when the users wants to remove an analysis session, the action will be enqueued, sometimes the
analysis session is huge and it takes time to be removed.
* Adding permission to user when it creates an analysis session
* Check permission to remove a analysis session
* adding support for Apache weblogs files. In essence ManaTI can support any kind of structured file

0.9.1a
----------
* When the user does a request to VirusTotal (by domain or IP), first the system try to use the VirusTotal API KEY completed in
user's profile, if it is null, they system uses the VirusTotal API KEY of ManaTI provided in the Parameters table (check migrations)

0.9.0a
----------
* NEW FILES STRUCTURE - it is based in the book **Cookiecutter Django**(https://github.com/pydanny/cookiecutter-django)
  and the book **Two Scoops of Django 1.11**(https://www.twoscoopspress.com/products/two-scoops-of-django-1-11) 😍
* Production settings with the new structure were not tested yet. Maybe running ManaTI in production mode can fail 😐😐
* Fixing bug the labelled weblogs in the table were updated but sync was not working properly and the bulk labelling
  were not reflecting and the server was still receiving request to label the same weblog
* Fixing when a new user is created, it has not access to editing profile.
* README file was updated
* Minor change in docker-compose settings
* The directory **/example_weblogs**, which contains several weblog files examples, it was move into **/docs**
* Adding .env.example and .env-docker.example files
* Adding management command **createsuperuser2**. It is equal to **createsuperuser** but now you can add parameters
  instead of using console inputs

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
