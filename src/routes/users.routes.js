import { Router } from "express";
import { userModel } from "../models/users.model.js";
import { createHash } from "../utils/bcrypt.js";

const userRouter = Router()

userRouter.post('/register', async(req,res) => {
    const {first_name, last_name, email, password, age} = req.body
    try{
        const hashPassword = createHash(password)
        const respuesta = await userModel.create({
            first_name: first_name,
            last_name: last_name,
            email: email,
            password: hashPassword,
            age: age
        })
        res.status(200).send({ mensaje: "Usuario creado", respuesta: respuesta});
    } catch(error) {
        res.status(400).send({error: `No se pudo registrar el usuario: ${error}`})
    }
})

userRouter.get('/details', async(req,res) => {
    const user = await userModel.findOne({email: req.session.email})
    res.render('user', {first_name: user.first_name, last_name: user.last_name, age: user.age, email: user.email, isLoged: req.session.email != undefined})
    console.log(user)
})

export default userRouter