const passport = require('passport')
const JwtStrategy = require('passport-jwt').Strategy
const LocalStrategy = require('passport-local').Strategy
const GooglePlusTokenStrategy = require('passport-google-plus-token')
const FacebookTokenStrategy = require('passport-facebook-token')
const { ExtractJwt } = require('passport-jwt')
const { JWT_SECRET } = require('../configs')

const User = require('../models/User')

// passport JWT
passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken('Authorization'),
    secretOrKey: JWT_SECRET
}, async (payload, done)=> {
    try {
        //
        const user = await User.findById(payload.sub)

        if(!user) return done(null, false)
        
        done(null, user)
    } catch (error) {
        done(error, false)
    }
}))

// passport Google
passport.use(new GooglePlusTokenStrategy({
    clientID: '493053929694-ad0neenregmr6sln3n8chhipujjqhu3e.apps.googleusercontent.com',
    clientSecret: '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'
}, async (accessToken, refreshToken, profile, done)=> {
    try {

        //check user exists in database
        const isExistUser = await User.findOne( {
            authGoogleID: profile.id,
            authType: 'google',
        })

        if(isExistUser)   return done(null, isExistUser)
        const newUser = new User({
            authType: 'google',
            authGoogleID: profile.id,
            email: profile.emails[0].value
        })
        await newUser.save()
        done(null, newUser)

    } catch (error) {
        done(error, false)
    }
}))

// passport facebook
passport.use(new FacebookTokenStrategy({
    clientID: '493053929694-ad0neenregmr6sln3n8chhipujjqhu3e.apps.googleusercontent.com',
    clientSecret: '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'
}, async (accessToken, refreshToken, profile, done)=> {
    try {

        //check user exists in database
        const isExistUser = await User.findOne( {
            authFacebookID: profile.id,
            authType: 'facebook',
        })

        if(isExistUser)   return done(null, isExistUser)
        const newUser = new User({
            authType: 'google',
            authFacebookID: profile.id,
            email: profile.emails[0].value,
            firstName: profile.name.givenName,
            lastName: profile.name.familyName,
        })
        await newUser.save()
        done(null, newUser)

    } catch (error) {
        done(error, false)
    }
}))

// passport local
passport.use(new LocalStrategy({
    usernameField: 'email'
}, async (email, password, done) => {
        //
    try {
        const user = await User.findOne({ email })

        if(!user) return done(null, false)
        
        const isValidPassword = await user.isValidPassword(password)
    
        if(!isValidPassword) return done(null, false)

    done(null, user)
    } catch (error) {
        done(error, false)
    }
}))