const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthToken } = require('adapt-authoring-auth');
const axios = require('axios');
const grant = require('grant-express');
/**
* Module which implements authentication with Github
* @extends {AbstractModule}
*/
class GithubAuthModule extends AbstractModule {
  constructor(...args) {
    super(...args);
    this.init();
  }
  async init() {
    // note we need to wait for sessions to boot so Grant initialises correctly
    const [ auth, server ] = await this.app.waitForModule('auth', 'server', 'sessions');

    auth.authentication.registerPlugin(this.getConfig('provider'), this);

    this.router = auth.router.createChildRouter(this.getConfig('provider'));

    server.api.expressRouter.use(grant({
      defaults: {
        protocol: 'http',
        host: 'localhost:5678',
        path: server.api.path,
        state: true
      },
      [this.getConfig('provider')]: {
        key: this.getConfig('clientID'),
        secret: this.getConfig('clientSecret'),
        callback: `${this.router.path}/callback`
      }
    }));
    this.router.addRoute({
      route: '/',
      handlers: { get: this.authenticate.bind(this) }
    }, {
      route: '/callback',
      handlers: { get: this.callback.bind(this) }
    });
    auth.unsecureRoute(`${this.router.path}/`, 'get');
    auth.unsecureRoute(`${this.router.path}/callback`, 'get');

    server.api.addMiddleware((req, res, next) => {
      const token = req.session && req.session.token;
      if(token && !req.headers.Authorization) {
        req.headers.Authorization = `Bearer ${token}`;
      }
      next();
    });

    this.setReady();
  }
  async authenticate(req, res, next) {
    res.redirect(`/api/connect/${this.getConfig('provider')}`);
  }
  async callback(req, res, next) {
    if(req.query.error) {
      return next(AuthError.Authenticate(req.query.error.error_description));
    }
    try {
      const ghData = await this.getUserProfile(req.query.access_token);
      const user = await this.findOrCreateUser(ghData);

      req.session.token = await AuthToken.generate(user);
      res.redirect('/');

    } catch(e) {
      next(e);
    }
  }
  async getUserProfile(token) {
    const response = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${token}` }
    });
    return response.data;
  }
  async findOrCreateUser({ email, name }) {
    const users = await this.app.waitForModule('users');
    const [user] = await users.find({ email });

    if(user) {
      return user;
    }
    const userData = { email };
    const names = name.split(' ');
    if(names.length > 1) { // not ideal, but should catch most cases
      userData.firstName = names[0];
      userData.lastName = names[names.length-1];
    }
    return users.insert(userData);
  }
}

module.exports = GithubAuthModule;
