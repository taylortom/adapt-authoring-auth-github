import { AbstractAuthModule, AuthToken } from 'adapt-authoring-auth'
import passport from 'passport'
import { Strategy as GitHubStrategy } from 'passport-github2'

/**
 * Module which implements authentication with Github
 * @memberof githubauth
 * @extends {AbstractAuthModule}
 */
class GithubAuthModule extends AbstractAuthModule {
  async setValues () {
    /** @ignore */ this.userSchema = 'githubauthuser'
    /** @ignore */ this.type = 'github'
  }

  /**
   * Initialises the module
   * @return {Promise}
   */
  async init () {
    await super.init()
    // wait for session support
    const [server, users] = await this.app.waitForModule('server', 'users', 'sessions')

    this.router.expressRouter.use(passport.initialize())
    this.router.expressRouter.use(passport.session())

    passport.use(new GitHubStrategy({
      clientID: this.getConfig('clientID'),
      clientSecret: this.getConfig('clientSecret'),
      callbackURL: `//${server.getConfig('host')}:${server.getConfig('port')}${this.router.path}/callback`
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let [user] = await users.find({ $or: profile.emails.map(({ value }) => ({ email: value })) })

        const registerUserWithRoles = this.getConfig('registerUserWithRoles')

        if (user) {
          return done(null, user)
        } else if (registerUserWithRoles.length) {
          user = await this.registerUser(profile, registerUserWithRoles)
          return done(null, user)
        } else {
          return done(null, false)
        }
      } catch (e) {
        return done(e)
      }
    }))

    passport.serializeUser(function (user, done) {
      done(null, user)
    })

    passport.deserializeUser(function (obj, done) {
      done(null, obj)
    })

    this.router.addRoute({
      route: '/',
      handlers: { get: passport.authenticate('github', { scope: ['user:email'] }) }
    }, {
      route: '/callback',
      handlers: { get: passport.authenticate('github', { failureRedirect: '/' }) }
    })

    // TODO: allow handlers to be an array rather than make separate calls to addRoute?
    this.router.addRoute({
      route: '/callback',
      handlers: { get: this.onAuthenticated.bind(this) }
    })

    this.unsecureRoute('/', 'get')
    this.unsecureRoute('/callback', 'get')
  }

  async registerUser (profile, roleNames) {
    const { displayName } = profile
    const email = profile.emails[0].value
    const nameParts = displayName.split(' ')
    const roles = await this.app.waitForModule('roles')
    const matchedRoles = await roles.find({ $or: roleNames.map(shortName => ({ shortName })) })

    return await this.register({
      email,
      firstName: nameParts.length !== 2 ? displayName : nameParts[0],
      lastName: nameParts.length !== 2 ? '' : nameParts[1],
      roles: matchedRoles.map(role => role._id.toString())
    })
  }

  /**
   * Performs post-authentication tasks
   * @param {ClientRequest} req
   * @param {ServerResponse} res
   * @param {Function} next
   */
  async onAuthenticated (req, res, next) {
    try {
      req.session.token = await AuthToken.generate(this.type, req.user)
      res.redirect('/')
    } catch (e) {
      return next(e)
    }
  }
}

export default GithubAuthModule
