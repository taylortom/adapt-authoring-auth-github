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
    const [ auth, server ] = await this.app.waitForModule('auth', 'server');

    auth.authentication.registerPlugin('github', this);

    server.api.expressRouter.use(grant({
      defaults: {
        protocol: 'http',
        host: 'localhost:5678',
        path: server.api.path,
        state: true
      },
      github: {
        key: 'Iv1.54410f732b02a761',
        secret: '7f34254ddc218f49781b84aac28e4f4163404aa4',
        callback: '/api/auth/github/callback'
      }
    }));
    server.api.addRoute({
      route: '/auth/github/callback',
      handlers: { get: this.callback.bind(this) }
    });
    auth.unsecureRoute('/api/auth/github/callback', 'get');

    this.setReady();
  }

  async authenticate(req, res, next) {
    const cookieData = this.getCookieData(req);

    if(cookieData.provider !== 'github') {
      return next();
    }
    res.redirect('http://localhost:5678/api/connect/github');
  }
  async callback(req, res, next) {
    if(req.query.error) {
      return next(new AuthError.Authenticate(req.query.error));
    }
    try {
      const ghData = await this.getUserProfile(req.query.access_token);
      const user = await this.findOrCreateUser(ghData);

      req.session.token = await AuthToken.generate(user);
      res.end();

    } catch(e) {
      next(e);
    }
  }
  async refresh(req, res, next) {

  }
  getCookieData(req) {
    return req.session && req.session.grant || {};
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
