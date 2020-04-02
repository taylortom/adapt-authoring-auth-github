const { AbstractModule } = require('adapt-authoring-core');
const { AuthError, AuthToken } = require('adapt-authoring-auth');
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

    this.setReady();
  }

  async authenticate(req, res, next) {
    res.send('authenticatedcorrectly');
  }
  async refresh(req, res, next) {

  }
}

module.exports = GithubAuthModule;
