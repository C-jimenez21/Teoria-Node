import dotenv from 'dotenv';
import express from 'express';
import { SignJWT, jwtVerify } from 'jose'; //trabaja clases todo los metodos los retorna una promesa
/**
 * SignJWT 
 */
dotenv.config();
const appExpress = express();


/**
 * ? No enviar datos sensibles si no es con autenticacion 2 pasos
 * * 
 * 
 */
appExpress.get('/:id/:nombre', async (req, res) => {
    //https://github.com/panva/jose/blob/main/docs/classes/jwt_sign.SignJWT.md
    let json = {
        id: req.params.id,
        nombre: req.params.nombre
    }
    const encoder = new TextEncoder(); 
    const jwtconstructor = new SignJWT({json}); // Se le asigna a la variable la isntacia de la clase SignJWT y se le asignan configuraciones las cuales son:
    const jwt = await jwtconstructor 
    .setProtectedHeader({alg: "HS256", typ:"JWT"}) //SetProtectedHeader({alg: "HS256" -> Es el algoritmo [de momento el mas seguro], typ: "JWT" -> como lo vas a codificar
    .setIssuedAt() //apuntarJWT_PRIVATE_KEY el servidor al que va a apuntar a ustedes en la red, Si se deja vacio este apunta a la pagina de JWT
    .setExpirationTime("1h") //Es el tiempo que va a durar el token en la red [1yr, 1day, 3seg (estandar)] El token debe ir encryptado en un objeto   
    .sign(encoder.encode(process.env.JWT_PRIVATE_KEY)); //la llave que le voy a poner para encryptar
    res.send({jwt});
})

appExpress.post('/', async (req, res)=>{
    //https://github.com/panva/jose/blob/main/docs/functions/jwt_verify./

    //console.log(req.headers);
 const {authorization} = req.headers;
 if(!authorization) return res.status(401).send({Token: "No pasa validacioin de autorizacion"})
 try{
    const encoder = new TextEncoder();
    const jwtData = await jwtVerify(
        authorization,
        encoder.encode(process.env.JWT_PRIVATE_KEY)
    );
    res.send(jwtData);
 }catch (error){
    res.status(401).send({Token: "Algo salio mal"});
 }
})

appExpress.listen(5010, ()=>{
    console.log('listening on port http://localhost:5010');
})

