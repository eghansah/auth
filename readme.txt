1. Direct user to the /login url
2. Display login form
3. Check for successful login when form is submitted
4. IF login is successful, redirect to successful login handler
5. Check if service parameter exists. If yes, create a cache entry with api_key of requesting service
   and the guid of the user that was requested. 
   Redirect with cache entry key

6. Service makes API call with key in header and the token received in step 5
7. If authentic, show user details

curl -H "X-API-KEY: DUQ0s4DozbGaEj6K6i1G9Wkbk0jPK9MVTTRmwJRqoReJDEoQD3ljjfdmPwxxkjhTf-8sOUnkvXG5a7JFu3iiGQ==" http://127.0.0.1:4000/api/verify_login?tk=c5q4ted4n6bj30t08afg