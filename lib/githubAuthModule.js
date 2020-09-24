const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthToken } = require('adapt-authoring-auth');
const axios = require('axios');
const grant = require('grant-express');
/**
 * Module which implements authentication with Github
 * @extends {AbstractModule}
 */
class GithubAuthModule extends AbstractModule {
  /** @override */
  constructor(...args) {
    super(...args);
    this.init();
  }
  /**
   * Initialises the module
   * @return {Promise}
   */
  async init() {
    // note we need to wait for sessions to boot so Grant initialises correctly
    const [ auth, server ] = await this.app.waitForModule('auth', 'server', 'sessions');
    /**
     * Reference to the AuthModule instance for easy access
     * @type {AuthModule}
     */
    this.auth = auth;
    /**
     * The auth provider
     * @type {String}
     */
    this.provider = this.getConfig('provider');

    auth.authentication.registerPlugin(this.provider, this);

    /**
     * Reference to the request router
     * @type {Router}
     */
    this.router = auth.router.createChildRouter(this.provider);

    const [protocol, host] = server.getConfig('url').split('://');

    server.api.expressRouter.use(grant({
      defaults: {
        protocol,
        host,
        path: server.api.path,
        state: true,
        transport: 'session'
      },
      [this.provider]: {
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
  /**
   * Performs the authentication
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async authenticate(req, res, next) {
    res.redirect(`/api/connect/${this.provider}`);
  }
  /**
   * Performs post-authentication tasks (called by Grant)
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async callback(req, res, next) {
    const response = req.session.grant.response;
    if(req.query.error) {
      return next(AuthError.Authenticate(response.error.error_description));
    }
    try {
      const ghData = await this.getUserProfile(response.access_token);
      const user = await this.auth.findOrCreateUser(this.provider, ghData.email, ghData);
      req.session.token = await AuthToken.generate(this.provider, user);
      res.redirect('/');
    } catch(e) {
      next(e);
    }
  }
  /**
   * Retrieves the user profile data via the GitHub API
   * @param {String} token The JWT
   * @return {Promise} Response with the user profile data
   */
  async getUserProfile(token) {
    const response = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${token}` }
    });
    // const data = { email: response.data.email };
    const data = { ...response.data };
    const names = data.name.split(' ');
    if(names.length > 1) { // not ideal, but should catch most cases
      data.firstName = names[0];
      data.lastName = names[names.length-1];
    }
    return data;
  }
}

module.exports = GithubAuthModule;
