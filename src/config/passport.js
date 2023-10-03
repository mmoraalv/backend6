import local from 'passport-local' //Estrategia
import passport from 'passport' //Manejador de las estrategias
import { createHash, validatePassword } from '../utils/bcrypt.js'
import { userModel } from '../models/users.model.js'

//Defino la estrategia a utilizar
const LocalStrategy = local.Strategy

const initializePassport = () => {
    //done es como si fuera un res.status(), el callback de respuesta
    passport.use('register', new LocalStrategy(
        { passReqToCallback: true, usernameField: 'email' }, async (req, username, password, done) => {
            //Defino como voy a registrar un user
            const { first_name, last_name, email, age } = req.body

            try {
                const user = await userModel.findOne({ email: username })
                if (user) {
                    //done es como si fuera un return de un callback
                    return done(null, false)
                }
                const passwordHash = createHash(password)
                const userCreated = await userModel.create({
                    first_name: first_name,
                    last_name: last_name,
                    email: email,
                    age: age,
                    password: passwordHash
                })
                console.log(userCreated)
                return done(null, userCreated)

            } catch (error) {
                return done(error)
            }
        }
    ))

     //Inicializar la session del usuario
     passport.serializeUser((user, done) => {
        done(null, user._id)
    })

    //Eliminar la session del usuario
    passport.deserializeUser(async (id, done) => {
        const user = await userModel.findById(id)
        done(null, user)
    })

    passport.use('login', new LocalStrategy({ usernameField: 'email' }, async (username, password, done) => {
        try {
            const user = await userModel.findOne({ email: email })

            if (!user) {
                return done(null, false)
            }

            if (validatePassword(password, user.password)) {
                return done(null, user) //Usuario y contraseña validos
            }

            return done(null, false) //Contraseña no valida

        } catch (error) {
            return done(error)
        }

    }))
}

export default initializePassport