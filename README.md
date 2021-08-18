# Stock Market Challenge

API service to get the latest stock market information. To consume the API, it's needed to sign up and log in.

## Postman collection

In the link below you can test the endpoint for both local and Heroku deploy

`https://www.getpostman.com/collections/7a49b5ffd6f4e52e9125`

## Deployment
### Local deploy

The project uses pipenv for the virtual environment. To install and run it:

```bash
pip install pipenv

#inside stock-market-challenge directory
pipenv sync
pipenv shell
```

Then, to run the application, execute the next command:

```bash
python main.py
```

The app will be running in localhost:8000

### Heroku deploy

The app is running in https://stock-market-chall.herokuapp.com


## Endpoint

The service has three endpoints. One for sign up, a second one to log in and get a token to use the last endpoint which is used to retrieve stock market information.

### /sign-up - POST

The endpoint needs a request body with user information to save the data to a database. Username and email address must be unique. The required json has the following structure:

```
{
  "username": "string",
  "name": "string",
  "last_name": "string",
  "email": "user@example.com",
  "password": "string"
}
```

### /token - POST

The endpoint receives username and password as form data and retrieves a token required to consume the /stock-info endpoint.

### /stock-info - GET

This endpoint returns the stock market information of the symbol passed to the endpoint as query parameter. To consume the endpoint, it's needed to be an authenticated user passing the token in the request header.

The endpoint can be consumed up to 5 times every 30 seconds. API call sample to get stock prices from Facebook:

`http://127.0.0.1:8000/stock-info/?symbol=FB`
