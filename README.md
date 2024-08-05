# Puntos Clave Modularidad

## Capa Config

### container.ts

Este código está utilizando un contenedor de inyección de dependencias de TypeScript llamado `tsyringe`. La inyección de dependencias es un patrón de diseño que permite a un objeto recibir sus dependencias de un contenedor, en lugar de crearlas por sí mismo. Esto mejora la modularidad y la facilidad de prueba del código.

### Descripción del Código

#### Importación del Contenedor y las Clases

```typescript
import { container } from "tsyringe";
import UserRepository from "../repositories/userRepository";
import UserService from "../services/userService";
import ProductRepository from "../repositories/productRepository";
import ProductService from "../services/productService";

```

Registro de singletons:

```typescript

container.registerSingleton<UserRepository>("UserRepository", UserRepository);
container.registerSingleton<UserService>("UserService", UserService);

container.registerSingleton<ProductRepository>("ProductRepository", ProductRepository);
container.registerSingleton<ProductService>("ProductService", ProductService);
```
Aquí se registran las clases como singletons en el contenedor. Un singleton es una instancia única de una clase que se reutiliza en toda la aplicación. El método registerSingleton toma dos parámetros:

Un identificador (en este caso, un string como "UserRepository" o "UserService") que se usa para referirse a la instancia.
La clase que se quiere registrar como singleton.
En resumen, este código configura un contenedor de inyección de dependencias con tsyringe, registrando varias clases (UserRepository, UserService, ProductRepository, y ProductService) como singletons, lo que permite que estas dependencias sean gestionadas y provistas automáticamente por el contenedor cuando se necesiten en otros lugares del código.

## Configuración de Conexión a la Base de Datos con Sequelize

Este archivo configura y establece una conexión a una base de datos utilizando Sequelize con TypeScript.

## Descripción del Código

### 1. Importaciones

```typescript
import { Sequelize } from 'sequelize-typescript';
import { config } from 'dotenv';
import { resolve } from 'path';
import { Dialect } from 'sequelize';
import UserModel from '../models/userModel';
import ProductModel from '../models/produtModel';
```
Sequelize: Se importa Sequelize desde sequelize-typescript para trabajar con modelos en TypeScript.
dotenv: config de dotenv se usa para cargar las variables de entorno desde un archivo .env.
path: resolve se usa para resolver rutas de archivos.
Dialect: Se importa Dialect desde sequelize para especificar el tipo de base de datos.
Modelos: Se importan los modelos de UserModel y ProductModel desde sus respectivas rutas.

###lecturas variables de entorno

```typescript
const dialect: Dialect | undefined = process.env.DB_DIALECT as Dialect;
const dbHost: string | undefined = process.env.DB_HOST;
const dbUser: string | undefined = process.env.DB_USER;
const dbPassword: string | undefined = process.env.DB_PASSWORD;
const dbName: string | undefined = process.env.DB_NAME;
```

### configuracion de sequelize

```typescript
const sequelize: Sequelize = new Sequelize({
    dialect: dialect,
    host: dbHost,
    username: dbUser,
    password: dbPassword,
    database: dbName,
    models: [UserModel, ProductModel]
});
```
Este código configura una conexión a una base de datos utilizando Sequelize y TypeScript. Carga las configuraciones de conexión desde un archivo .env, valida que todas las variables de entorno necesarias estén presentes y luego crea una instancia de Sequelize configurada con esas variables. Esta instancia se exporta para ser utilizada en otros módulos de la aplicación.

## Capa Controller

Este código define un controlador de autenticación (AuthController) para una aplicación web utilizando Express y TypeScript. El controlador maneja el inicio de sesión y el registro de usuarios, además de generar tokens JWT para la autenticación. Aquí tienes una explicación detallada de lo que está sucediendo:

###Importaciones

```typescript
import { container } from "tsyringe";
import { Request, Response } from "express";
import { config } from "dotenv";
import { resolve } from "path";
import jwt from "jsonwebtoken";
import UserService from "../services/userService";
import { UserType } from "../interfaces/user";
```
tsyringe: Se importa el contenedor de inyección de dependencias.
Express: Se importan Request y Response para manejar solicitudes y respuestas HTTP.
dotenv: config de dotenv se usa para cargar las variables de entorno desde un archivo .env.
path: resolve se usa para resolver rutas de archivos.
jsonwebtoken: Se importa jsonwebtoken para generar y verificar tokens JWT.
UserService: Se importa UserService, que maneja la lógica de negocio relacionada con los usuarios.
UserType: Se importa UserType para definir el tipo de datos del usuario.

###clase AouthController metodo login

```typescript
static async login(req: Request, res: Response) {
    try {
        const { email, password } = req.body;
        const userService = container.resolve(UserService);
        const user = await userService.checkUserCredentials(email, password);
        if (!user || !user.id || !user.name) {
            return res.status(401).json({
                status: 401,
                message: "Invalid credentials"
            });
        }
        const token = AuthController.generateToken({ id: user.id, username: user.name });
        res.status(200).json({ token });
    } catch (err: any) {
        res.status(401).json({
            status: 401,
            message: err.message
        });
    }
}
```
Descripción: Este método maneja el inicio de sesión.
Proceso:
Extrae email y password del cuerpo de la solicitud (req.body).
Resuelve la instancia de UserService usando tsyringe.
Llama al método checkUserCredentials de UserService para verificar las credenciales del usuario.
Si las credenciales no son válidas, devuelve un estado 401 con un mensaje de "Invalid credentials".
Si las credenciales son válidas, genera un token JWT usando el método generateToken.
Devuelve el token en la respuesta con un estado 200.

###Metodo register

```typescript
static async register(req: Request, res: Response) {
    try {
        const { name, email, password }: UserType = req.body;
        const userService = container.resolve(UserService);
        const user = await userService.createUser({ name, email, password });
        res.status(201).json({
            status: 201,
            user
        });
    } catch (err: any) {
        res.status(400).json({
            status: 400,
            message: err.message
        });
    }
}
```
Descripción: Este método maneja el registro de nuevos usuarios.
Proceso:
Extrae name, email y password del cuerpo de la solicitud (req.body).
Resuelve la instancia de UserService usando tsyringe.
Llama al método createUser de UserService para crear un nuevo usuario.
Devuelve el nuevo usuario en la respuesta con un estado 201.
Si hay algún error, devuelve un estado 400 con el mensaje de error.

###Metodo generate Token

```typescript
static generateToken(user: { id: number; username: string }): any {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error("Please provide a JWT secret!");
    }
    const token = jwt.sign(user, secret, { expiresIn: "1h" });
    return token;
}
```
Descripción: Este método genera un token JWT.
Proceso:
Extrae el secreto JWT de las variables de entorno.
Si el secreto no está definido, lanza un error.
Genera un token JWT que contiene la información del usuario (id y username).
El token expira en 1 hora.
Devuelve el token.

Este código define un controlador de autenticación (AuthController) que maneja las solicitudes de inicio de sesión y registro de usuarios, utilizando servicios proporcionados por UserService. También incluye la generación de tokens JWT para la autenticación. La configuración de variables de entorno se maneja con dotenv, y la inyección de dependencias se realiza con tsyringe.

### controller product

Este código define un controlador de productos (ProductController) para una aplicación web utilizando Express y TypeScript. El controlador maneja las operaciones CRUD (Crear, Leer, Actualizar, Eliminar) para los productos mediante el uso de servicios proporcionados por ProductService. Aquí tienes una explicación detallada de lo que está sucediendo en cada parte del código:

Importaciones
typescript
Copiar código
import ProductService from "../services/productService";
import { container } from "tsyringe";
import { Request, Response } from "express";
import { ProductType } from "../interfaces/product";
ProductService: Se importa ProductService que maneja la lógica de negocio relacionada con los productos.
tsyringe: Se importa el contenedor de inyección de dependencias.
Express: Se importan Request y Response para manejar solicitudes y respuestas HTTP.
ProductType: Se importa ProductType para definir el tipo de datos del producto.
Clase ProductController
Método getAllProducts
typescript
Copiar código
static async getAllProducts(req: Request, res: Response) {
    try {
        const productService: ProductService = container.resolve(ProductService);
        const products: ProductType[] = await productService.getAllProducts();
        res.status(200).json({
            status: 200,
            products: products
        });
    } catch (err: any) {
        res.status(500).json({
            status: 500,
            message: err.message
        });
    }
}
Descripción: Este método maneja la obtención de todos los productos.
Proceso:
Resuelve la instancia de ProductService usando tsyringe.
Llama al método getAllProducts de ProductService para obtener todos los productos.
Devuelve los productos en la respuesta con un estado 200.
Si hay un error, devuelve un estado 500 con el mensaje de error.
Método getProductById
typescript
Copiar código
static async getProductById(req: Request, res: Response) {
    try {
        const productService: ProductService = container.resolve(ProductService);
        const id: number = parseInt(req.params.id);
        const product: ProductType | null = await productService.getProductById(id);
        if (!product) {
            res.status(404).json({
                status: 404,
                message: 'Product not found'
            });
            return;
        }
        res.status(200).json({
            status: 200,
            product
        });
    } catch (err: any) {
        res.status(500).json({
            status: 500,
            message: err.message
        });
    }
}
Descripción: Este método maneja la obtención de un producto por su ID.
Proceso:
Resuelve la instancia de ProductService usando tsyringe.
Extrae el ID del producto de los parámetros de la solicitud (req.params.id).
Llama al método getProductById de ProductService para obtener el producto.
Si el producto no se encuentra, devuelve un estado 404 con un mensaje de "Product not found".
Si se encuentra, devuelve el producto en la respuesta con un estado 200.
Si hay un error, devuelve un estado 500 con el mensaje de error.
Método createProduct
typescript
Copiar código
static async createProduct(req: Request, res: Response) {
    try {
        const productService: ProductService = container.resolve(ProductService);
        const product: ProductType = req.body;
        const newProduct: ProductType | null = await productService.createProduct(product);
        res.status(201).json({
            status: 201,
            product: newProduct
        });
    } catch (err: any) {
        res.status(500).json({
            status: 500,
            message: err.message
        });
    }
}
Descripción: Este método maneja la creación de un nuevo producto.
Proceso:
Resuelve la instancia de ProductService usando tsyringe.
Extrae el producto del cuerpo de la solicitud (req.body).
Llama al método createProduct de ProductService para crear el nuevo producto.
Devuelve el nuevo producto en la respuesta con un estado 201.
Si hay un error, devuelve un estado 500 con el mensaje de error.
Método updateProduct
typescript
Copiar código
static async updateProduct(req: Request, res: Response) {
    const productService: ProductService = container.resolve(ProductService);
    const id: number = parseInt(req.params.id);
    const product: Partial<ProductType> = req.body;
    try {
        const [affectedCount]: number[] = await productService.updateProduct(id, product);
        if (affectedCount === 0) {
            res.status(404).json({
                status: 404,
                message: 'Product not found'
            });
            return;
        }
        res.status(200).json({
            status: 200,
            message: 'Product updated'
        });
    } catch (err: any) {
        res.status(500).json({
            status: 500,
            message: err.message
        });
    }
}
Descripción: Este método maneja la actualización de un producto existente.
Proceso:
Resuelve la instancia de ProductService usando tsyringe.
Extrae el ID del producto de los parámetros de la solicitud (req.params.id).
Extrae el producto actualizado del cuerpo de la solicitud (req.body).
Llama al método updateProduct de ProductService para actualizar el producto.
Si no se afecta ningún producto (producto no encontrado), devuelve un estado 404 con un mensaje de "Product not found".
Si se actualiza correctamente, devuelve un mensaje de éxito con un estado 200.
Si hay un error, devuelve un estado 500 con el mensaje de error.
Método deleteProduct
typescript
Copiar código
static async deleteProduct(req: Request, res: Response) {
    const productService: ProductService = container.resolve(ProductService);
    const id: number = parseInt(req.params.id);
    try {
        const deletedCount: number = await productService.deleteProduct(id);
        if (deletedCount === 0) {
            res.status(404).json({
                status: 404,
                message: 'Product not found'
            });
            return;
        }
        res.status(200).json({
            status: 200,
            message: 'Product deleted'
        });
    } catch (err: any) {
        res.status(500).json({
            status: 500,
            message: err.message
        });
    }
}
Descripción: Este método maneja la eliminación de un producto existente.
Proceso:
Resuelve la instancia de ProductService usando tsyringe.
Extrae el ID del producto de los parámetros de la solicitud (req.params.id).
Llama al método deleteProduct de ProductService para eliminar el producto.
Si no se elimina ningún producto (producto no encontrado), devuelve un estado 404 con un mensaje de "Product not found".
Si se elimina correctamente, devuelve un mensaje de éxito con un estado 200.
Si hay un error, devuelve un estado 500 con el mensaje de error.
Resumen
Este código define un controlador de productos (ProductController) que maneja las solicitudes CRUD para los productos utilizando servicios proporcionados por ProductService. La inyección de dependencias se realiza con tsyringe, y las respuestas HTTP se manejan con Express.

##Capa Interfaces

Este código define una interfaz de TypeScript llamada ProductType, que especifica la estructura de un objeto de producto en la aplicación. Una interfaz en TypeScript es una forma de definir la forma y los tipos de datos que un objeto debe tener. Aquí está la explicación de cada parte de la interfaz:

```typescript
export interface ProductType {
    id?: number;
    name: string;
    description: string;
    price: number;
    stock: number;
    category: string;
}
```

id?: number: Define un campo opcional id que es de tipo number. El signo de interrogación (?) indica que este campo es opcional, lo que significa que un objeto que implemente esta interfaz puede o no tener un id.
name: string: Define un campo name que es de tipo string. Este campo es obligatorio, por lo que cada objeto que implemente esta interfaz debe tener un name.
description: string: Define un campo description que es de tipo string. Este campo también es obligatorio.
price: number: Define un campo price que es de tipo number. Este campo es obligatorio.
stock: number: Define un campo stock que es de tipo number. Este campo es obligatorio.
category: string: Define un campo category que es de tipo string. Este campo es obligatorio.
Propósito de la Interfaz
La interfaz ProductType sirve como un contrato que define qué propiedades debe tener un objeto de producto y qué tipos de datos deben tener estas propiedades. Al usar esta interfaz, TypeScript puede garantizar que los objetos de producto que se usan en la aplicación tengan la forma esperada y contengan los datos necesarios. Esto ayuda a prevenir errores y a mejorar la autocompletación y la documentación en los editores de código.

## Middlewares

Este middleware authJWT se utiliza en una aplicación Express para autenticar las solicitudes HTTP utilizando JSON Web Tokens (JWT). Aquí está una explicación detallada de lo que hace cada parte del código:

```typescript

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from 'dotenv';
import { resolve } from 'path';
```
Express: Se importan Request, Response y NextFunction de Express para manejar las solicitudes, respuestas y la siguiente función de middleware en la cadena.
jsonwebtoken: Se importa jwt para manejar la verificación de los tokens JWT.
dotenv: Se importa config de dotenv para cargar las variables de entorno desde un archivo .env.
path: Se importa resolve para resolver rutas de archivos.

Interfaz CustomRequest
typescript
Copiar código
interface CustomRequest extends Request {
    user?: any;
}
CustomRequest: Extiende la interfaz Request de Express para incluir una propiedad opcional user. Esto se utiliza para almacenar la información del usuario autenticado.

###Función Middleware authJWT

```typescript
const authJWT = (req: CustomRequest, res: Response, next: NextFunction) => {
    const authHeader: string | undefined = req.headers.authorization;

    if (authHeader) {
        const token: string = authHeader.split(' ')[1];
        const secret: string | undefined = process.env.JWT_SECRET;

        if (!secret) {
            res.status(500).json({
                status: 500,
                message: 'secret not found'
            });
            return;
        }

        jwt.verify(token, secret, (err, user) => {
            if (err) {
                res.status(403).json({
                    status: 403,
                    message: 'Forbidden'
                });
                return;
            }
            req.user = user;
            next();
        });
    } else {
        res.status(401).json({
            status: 401,
            message: 'Unauthorized'
        });
    }
};

```

Descripción y Proceso
Obtener el encabezado de autorización:

typescript
Copiar código
const authHeader: string | undefined = req.headers.authorization;
Se obtiene el encabezado de autorización de la solicitud.

Verificar si el encabezado de autorización está presente:

Si el encabezado de autorización está presente, extrae el token JWT.
Obtiene la clave secreta (JWT_SECRET) del archivo .env.
Si no se encuentra la clave secreta, responde con un estado 500 (Error interno del servidor).
Verifica el token utilizando jwt.verify(). Si el token es inválido o ha expirado, responde con un estado 403 (Prohibido).
Si el token es válido, almacena la información del usuario en req.user y llama a next() para pasar al siguiente middleware.
Si el encabezado de autorización no está presente, responde con un estado 401 (No autorizado).

Resumen
Este middleware authJWT se utiliza para proteger las rutas de la aplicación verificando que la solicitud incluya un token JWT válido en el encabezado de autorización. Si el token es válido, el middleware almacena la información del usuario en la solicitud y permite que la solicitud continúe hacia el siguiente middleware o controlador. Si el token es inválido o falta, responde con el estado HTTP adecuado (401 o 403).

###Función Middleware errorHandler

```typescript
const errorHandler = (err: any, req: Request, res: Response, next: NextFunction): void => {
    console.error(err.stack);
    res.status(500).json({ message: "Internal server error" });
}
```
Descripción y Proceso
Definición de la función errorHandler:

```typescript
const errorHandler = (err: any, req: Request, res: Response, next: NextFunction): void => {
```
Se define una función llamada errorHandler que toma cuatro parámetros: err, req, res, y next.
err: El objeto de error que se pasó a este middleware.
req: El objeto de solicitud de Express.
res: El objeto de respuesta de Express.
next: La función next que se usa para pasar el control al siguiente middleware, aunque en este caso no se utiliza.

registro del error

console.error(err.stack);
Se registra el stack trace del error en la consola del servidor. Esto es útil para depurar problemas y ver dónde ocurrió el error en el código.
Enviar una respuesta al cliente:

```typescript
res.status(500).json({ message: "Internal server error" });
```
Se envía una respuesta al cliente con un estado HTTP 500 (Error interno del servidor).
El cuerpo de la respuesta es un objeto JSON que contiene un mensaje genérico de error: { message: "Internal server error" }.

Resumen
Este middleware errorHandler captura todos los errores no manejados que ocurren en la aplicación Express. Cuando se lanza un error, este middleware:

Registra el stack trace del error en la consola para facilitar la depuración.
Envía una respuesta al cliente con un estado HTTP 500 (Error interno del servidor) y un mensaje genérico de error.
Este middleware es útil para asegurar que todos los errores no manejados sean capturados y registrados, proporcionando una respuesta consistente al cliente cuando ocurre un error en el servidor.

## Capa models

Este código define un modelo de Sequelize llamado ProductModel utilizando TypeScript y decoradores. Sequelize es una biblioteca de ORM (Object-Relational Mapping) para Node.js, que permite interactuar con bases de datos SQL de manera más sencilla. A continuación, se explica cada parte del código:

Importaciones

```typescript
import UserModel from './userModel';
import {
    Table,
    Column,
    Model,
    DataType,
    PrimaryKey,
    AutoIncrement,
    HasMany,
    ForeignKey,
    BelongsTo
} from 'sequelize-typescript';
```
UserModel: Importa el modelo UserModel para definir una relación de clave externa con ProductModel.
sequelize-typescript: Importa varios decoradores y tipos de Sequelize necesarios para definir el modelo y sus propiedades.

Decorador @Table

```typescript
@Table({
    tableName: 'products',
    timestamps: true
})
```
@Table: Este decorador define la configuración de la tabla en la base de datos. Aquí, la tabla se llama products y se incluyen automáticamente las columnas createdAt y updatedAt (timestamps: true).

Clase ProductModel
```typescript
export default class ProductModel extends Model<ProductModel> {
```
ProductModel: Define la clase ProductModel que extiende de Model, lo que permite que Sequelize trate esta clase como un modelo para la tabla products.

Definición de Columnas

    @PrimaryKey
    @AutoIncrement
    @Column({
        type: DataType.INTEGER
    })
    id!: number;

@PrimaryKey: Indica que id es la clave primaria.
@AutoIncrement: Indica que id se auto-incrementa.
@Column: Define el tipo de datos y las opciones para la columna id.

    @Column({
        type: DataType.STRING,
        allowNull: false
    })
    name!: string;

@Column: Define una columna name de tipo STRING que no puede ser nula

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    description!: string;
@Column: Define una columna description de tipo STRING que no puede ser nula.

    @Column({
        type: DataType.DECIMAL,
        allowNull: false,
    })
    price!: number;
@Column: Define una columna price de tipo DECIMAL que no puede ser nula.

    @Column({
        type: DataType.INTEGER,
        allowNull: false,
    })
    stock!: number;
@Column: Define una columna stock de tipo INTEGER que no puede ser nula.

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    category!: string;
@Column: Define una columna category de tipo STRING que no puede ser nula.

Relación con UserModel

    @ForeignKey(() => UserModel)
    @Column({
        type: DataType.INTEGER,
        allowNull: false,
    })
    userId!: number;

    @BelongsTo(() => UserModel)
    user!: UserModel;

@ForeignKey: Define userId como una clave foránea que referencia a la tabla users (definida por UserModel).
@BelongsTo: Define la relación de pertenencia, indicando que cada producto pertenece a un usuario (UserModel).

Resumen
Este modelo ProductModel representa una tabla products en la base de datos con las siguientes columnas:

id: Clave primaria, auto-incremental.
name: Nombre del producto, no nulo.
description: Descripción del producto, no nulo.
price: Precio del producto, no nulo.
stock: Cantidad de stock del producto, no nulo.
category: Categoría del producto, no nulo.
userId: Clave foránea que referencia a un usuario en UserModel, no nulo.
Además, establece una relación de pertenencia con el modelo UserModel, lo que permite acceder a los datos del usuario asociado a cada producto.

##Capa Repositories

Este código define una clase ProductRepository que actúa como un repositorio para manejar las operaciones de base de datos relacionadas con los productos utilizando Sequelize y TypeScript. La clase está decorada con el decorador @injectable() de tsyringe para permitir la inyección de dependencias. A continuación, se explica cada parte del código:

import { injectable } from "tsyringe";
import ProductModel from "../models/produtModel";
import { ProductType } from "../interfaces/product";

@injectable: Importa el decorador injectable de tsyringe para habilitar la inyección de dependencias.
ProductModel: Importa el modelo ProductModel, que representa la tabla products en la base de datos.
ProductType: Importa la interfaz ProductType, que define la estructura de un producto.

Decorador @injectable()

@injectable()

@injectable(): Marca la clase ProductRepository como inyectable, permitiendo que sea gestionada por el contenedor de dependencias de tsyringe.

Clase ProductRepository
typescript
Copiar código
export default class ProductRepository {
ProductRepository: Define la clase ProductRepository que contiene métodos para realizar operaciones CRUD (Crear, Leer, Actualizar, Eliminar) en la tabla products.

###Metodos

findAll

```typescript
async findAll(): Promise<ProductType[]>{
    return await ProductModel.findAll();
}
```
findAll: Recupera todos los productos de la base de datos. Utiliza el método findAll() de Sequelize para obtener todos los registros de la tabla products y devuelve una promesa que se resuelve con una lista de objetos ProductType.

findById

```typescript
async findById(id: number): Promise<ProductType | null>{
    return await ProductModel.findByPk(id);
}
```
findById: Busca un producto por su identificador (ID). Utiliza el método findByPk(id) de Sequelize para encontrar un registro por su clave primaria y devuelve una promesa que se resuelve con el objeto ProductType correspondiente o null si no se encuentra ningún registro.

create
```typescript
async create(product: Partial<ProductType>): Promise<ProductType>{
   return await ProductModel.create(product as ProductModel);
}
```

create: Crea un nuevo producto en la base de datos. Utiliza el método create(product) de Sequelize para insertar un nuevo registro y devuelve una promesa que se resuelve con el objeto ProductType creado.

update
```typescript
async update(id: number, product: Partial<ProductType>): Promise<[number]>{
    return await ProductModel.update(product, {where: {id}});
}
```
update: Actualiza un producto existente en la base de datos. Utiliza el método update(product, { where: { id } }) de Sequelize para actualizar el registro con el ID especificado y devuelve una promesa que se resuelve con un arreglo que contiene el número de registros afectados.

delete
```typescript
async delete(id: number): Promise<number>{
    return await ProductModel.destroy({where: {id}});
}
```
delete: Elimina un producto de la base de datos. Utiliza el método destroy({ where: { id } }) de Sequelize para eliminar el registro con el ID especificado y devuelve una promesa que se resuelve con el número de registros eliminados.

Resumen
La clase ProductRepository proporciona una interfaz para interactuar con la tabla products en la base de datos. Utiliza los métodos de Sequelize para realizar operaciones CRUD. Cada método devuelve una promesa que se resuelve con los datos correspondientes o el número de registros afectados. La clase está configurada para ser inyectada en otras partes de la aplicación utilizando tsyringe, lo que facilita la gestión de dependencias y la separación de responsabilidades.

##Capa Routes

Este código configura y exporta un enrutador para una aplicación Express. A continuación, se detalla qué hace cada parte del código:

Importaciones
```typescript

import { Router } from "express";
import authJWT from "../middlewares/auth";
import { authRouter, userRouter, productRouter } from "./index";
```
Router: Importa el constructor de enrutadores de Express, que se usa para definir rutas en la aplicación.
authJWT: Importa un middleware de autenticación JWT que se usa para proteger ciertas rutas.
authRouter, userRouter, productRouter: Importa los enrutadores para la autenticación, usuarios y productos, respectivamente, desde el archivo ./index.

Configuración del Enrutador

```typescript

const router: Router = Router();
```
const router: Router = Router();: Crea una instancia de enrutador de Express que se utilizará para definir las rutas principales de la aplicación.

Definición de Rutas
```typescript
router.use("/auth", authRouter);
```
router.use("/auth", authRouter);: Define una ruta base /auth que utiliza el enrutador authRouter. Esto significa que todas las rutas definidas en authRouter estarán disponibles bajo /auth. Por ejemplo, si authRouter define una ruta /login, la ruta completa sería /auth/login.

typescript
router.use("/users", authJWT, userRouter);
router.use("/users", authJWT, userRouter);: Define una ruta base /users que utiliza el middleware authJWT para autenticar las solicitudes y el enrutador userRouter para manejar las rutas relacionadas con los usuarios. Esto significa que todas las rutas en userRouter estarán disponibles bajo /users y requieren autenticación JWT. Por ejemplo, si userRouter define una ruta /profile, la ruta completa sería /users/profile.

typescript
router.use("/products", authJWT, productRouter);
router.use("/products", authJWT, productRouter);: Define una ruta base /products que utiliza el middleware authJWT para autenticar las solicitudes y el enrutador productRouter para manejar las rutas relacionadas con los productos. Al igual que con las rutas de usuarios, todas las rutas en productRouter estarán disponibles bajo /products y requieren autenticación JWT. Por ejemplo, si productRouter define una ruta /list, la ruta completa sería /products/list.

Exportación

typescript
export default router;
export default router;: Exporta el enrutador configurado para que pueda ser utilizado en otras partes de la aplicación, generalmente en el archivo principal del servidor donde se montará este enrutador.

Resumen
Este código crea un enrutador de Express que organiza las rutas de la aplicación en tres secciones principales:

/auth: Manejado por authRouter, sin necesidad de autenticación.
/users: Manejado por userRouter y protegido por el middleware de autenticación JWT (authJWT).
/products: Manejado por productRouter y también protegido por el middleware de autenticación JWT (authJWT).
El enrutador se exporta para su uso en la aplicación principal.

###AuthRouter

Este código define un enrutador para manejar las rutas relacionadas con la autenticación en una aplicación Express. A continuación, se desglosa lo que está ocurriendo:

Importaciones
typescript
Copiar código
import { Router } from "express";
import AuthController from "../controllers/authController";
Router: Importa el constructor de enrutadores de Express, utilizado para definir y gestionar rutas en la aplicación.
AuthController: Importa el controlador AuthController, que contiene la lógica para manejar las solicitudes de autenticación, como el inicio de sesión y el registro de usuarios.
Configuración del Enrutador
typescript
Copiar código
export const authRouter: Router = Router();
export const authRouter: Router = Router();: Crea una instancia del enrutador de Express y la exporta. Este enrutador se utilizará para definir las rutas relacionadas con la autenticación.
Definición de Rutas
typescript
Copiar código
authRouter.post("/login", AuthController.login);
authRouter.post("/login", AuthController.login);: Define una ruta POST en /login que utiliza el método login del AuthController para manejar las solicitudes de inicio de sesión. Cuando se recibe una solicitud POST en /login, se invoca el método login del AuthController para procesar la autenticación del usuario.
typescript
Copiar código
authRouter.post("/register", AuthController.register);
authRouter.post("/register", AuthController.register);: Define una ruta POST en /register que utiliza el método register del AuthController para manejar las solicitudes de registro de nuevos usuarios. Cuando se recibe una solicitud POST en /register, se invoca el método register del AuthController para crear un nuevo usuario en el sistema.
Resumen
Este código configura un enrutador para las rutas de autenticación de la aplicación:

/login: Ruta POST que maneja el inicio de sesión de los usuarios mediante el método login del AuthController.
/register: Ruta POST que maneja el registro de nuevos usuarios mediante el método register del AuthController.
El enrutador authRouter se exporta para ser utilizado en otras partes de la aplicación, generalmente se monta en un archivo de enrutamiento principal como se mostró en el código anterior.

### ProductRouter.ts

Definición de Rutas
Obtener todos los productos

typescript
Copiar código
productRouter.get("/", ProductController.getAllProducts);
productRouter.get("/", ProductController.getAllProducts);: Define una ruta GET en / (raíz del enrutador de productos) que utiliza el método getAllProducts del ProductController para manejar las solicitudes que obtienen todos los productos.
Obtener un producto por ID

typescript
Copiar código
productRouter.get("/:id", ProductController.getProductById);
productRouter.get("/:id", ProductController.getProductById);: Define una ruta GET en /:id, donde :id es un parámetro de ruta. Utiliza el método getProductById del ProductController para manejar las solicitudes que obtienen un producto específico basado en su ID.
Crear un nuevo producto

typescript
Copiar código
productRouter.post("/", ProductController.createProduct);
productRouter.post("/", ProductController.createProduct);: Define una ruta POST en / que utiliza el método createProduct del ProductController para manejar las solicitudes que crean un nuevo producto.
Actualizar un producto existente

typescript
Copiar código
productRouter.put("/:id", ProductController.updateProduct);
productRouter.put("/:id", ProductController.updateProduct);: Define una ruta PUT en /:id, donde :id es un parámetro de ruta. Utiliza el método updateProduct del ProductController para manejar las solicitudes que actualizan un producto existente basado en su ID.
Eliminar un producto

typescript
Copiar código
productRouter.delete("/:id", ProductController.deleteProduct);
productRouter.delete("/:id", ProductController.deleteProduct);: Define una ruta DELETE en /:id, donde :id es un parámetro de ruta. Utiliza el método deleteProduct del ProductController para manejar las solicitudes que eliminan un producto existente basado en su ID.

Resumen
Este código configura un enrutador para las rutas de productos en la aplicación Express. Las rutas definidas son:

GET /: Obtiene todos los productos, manejado por el método getAllProducts del ProductController.
GET /:id: Obtiene un producto específico por su ID, manejado por el método getProductById del ProductController.
POST /: Crea un nuevo producto, manejado por el método createProduct del ProductController.
PUT /:id: Actualiza un producto existente por su ID, manejado por el método updateProduct del ProductController.
DELETE /:id: Elimina un producto existente por su ID, manejado por el método deleteProduct del ProductController.
El enrutador productRouter se exporta para ser utilizado en otras partes de la aplicación, típicamente en el archivo de enrutamiento principal.

## Capa services

ProductRepository: Importa la clase del repositorio de productos, que maneja las operaciones CRUD en la base de datos.
injectable y inject: Importa decoradores de tsyringe para la inyección de dependencias. injectable marca la clase para ser inyectable, y inject se utiliza para inyectar dependencias en el constructor.
ProductModel: Importa el modelo de producto que define la estructura del producto en la base de datos.
ProductType: Importa una interfaz que define el tipo de datos de un producto.

Clase ProductService

  @injectable()
  export default class ProductService {
    constructor(@inject('ProductRepository') private productRepository: ProductRepository) {}

@injectable(): Marca la clase ProductService como inyectable, lo que significa que puede recibir dependencias a través del contenedor de tsyringe.
constructor(@inject('ProductRepository') private productRepository: ProductRepository): Inyecta una instancia de ProductRepository en el constructor de ProductService. El decorador @inject('ProductRepository') le dice al contenedor de tsyringe que inyecte la dependencia registrada con el identificador 'ProductRepository'.

Métodos de ProductService
getAllProducts()

typescript
Copiar código
async getAllProducts(): Promise<ProductType[]> {
    return await this.productRepository.findAll();
}
Llama al método findAll del repositorio para obtener todos los productos.
getProductById(id: number)

typescript
Copiar código
async getProductById(id: number): Promise<ProductType | null> {
    return await this.productRepository.findById(id);
}
Llama al método findById del repositorio para obtener un producto específico por su ID.
createProduct(product: Partial<ProductModel>)

typescript
Copiar código
async createProduct(product: Partial<ProductModel>): Promise<ProductType | null> {
    return await this.productRepository.create(product);
}
Llama al método create del repositorio para crear un nuevo producto. product es de tipo Partial<ProductModel>, lo que significa que puede no contener todas las propiedades del modelo ProductModel.
updateProduct(id: number, product: Partial<ProductType>)

typescript
Copiar código
async updateProduct(id: number, product: Partial<ProductType>): Promise<[affectedCount: number]> {
    return await this.productRepository.update(id, product);
}
Llama al método update del repositorio para actualizar un producto existente por su ID. Devuelve un array con el número de registros afectados.
deleteProduct(id: number)

typescript
Copiar código
async deleteProduct(id: number): Promise<number> {
    return await this.productRepository.delete(id);
}
Llama al método delete del repositorio para eliminar un producto por su ID. Devuelve el número de registros eliminados.

Resumen
La clase ProductService gestiona la lógica de negocio relacionada con los productos y utiliza ProductRepository para interactuar con la base de datos. Los métodos del servicio delegan las operaciones CRUD al repositorio inyectado, promoviendo una separación de responsabilidades y facilitando la prueba y el mantenimiento del código. La inyección de dependencias con tsyringe permite una gestión más flexible y modular de las dependencias en la aplicación.

##Capa index.ts

Este código configura y arranca una aplicación Express en Node.js, integrando varias dependencias y configuraciones esenciales. A continuación, se desglosa lo que está ocurriendo:

1. Limpieza de Consola y Carga de Módulos

```typescript

   console.clear();
import "reflect-metadata";
import './config/container';
import express, { Application } from 'express';
import sequelize from './config/db';
import router from './routes/Router';
import errorHandler from './middlewares/errorHandler';
import cors from 'cors';
```
console.clear();: Limpia la consola, lo cual es útil para iniciar el servidor sin información de ejecuciones anteriores.
import "reflect-metadata";: Importa reflect-metadata, necesario para el funcionamiento de tsyringe y otras bibliotecas que dependen de la reflexión de metadatos.
import './config/container';: Importa la configuración de inyección de dependencias, que probablemente registre las dependencias con tsyringe.
import express, { Application } from 'express';: Importa Express y su tipo Application para crear y configurar la aplicación.
import sequelize from './config/db';: Importa la instancia de Sequelize configurada para interactuar con la base de datos.
import router from './routes/Router';: Importa el enrutador principal que define las rutas de la API.
import errorHandler from './middlewares/errorHandler';: Importa el middleware para manejar errores en la aplicación.
import cors from 'cors';: Importa el middleware cors para manejar solicitudes entre dominios.

2. Configuración de la Aplicación

```typescript
const PORT: number | string = process.env.PORT || 3000;
const app: Application = express();
```
const PORT: number | string = process.env.PORT || 3000;: Define el puerto en el que el servidor escuchará. Utiliza el puerto definido en las variables de entorno o 3000 por defecto.
const app: Application = express();: Crea una instancia de la aplicación Express.

3. Configuración de Middlewares

   app.use(cors());
   
app.use(cors());: Habilita CORS (Cross-Origin Resource Sharing) con configuraciones predeterminadas.

```typescript

  const corsOptions = {
    origin: "http://localhost:4200",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    allowedHeaders: "Content-Type,Authorization",
    credentials: true
};

app.use(cors(corsOptions));
```
const corsOptions = {...};: Configura opciones específicas para CORS, permitiendo solicitudes desde http://localhost:4200, especificando métodos permitidos, cabeceras permitidas, y habilitando el soporte de credenciales.
app.use(cors(corsOptions));: Aplica la configuración CORS a la aplicación Express.

```typescript
app.use(express.json());
```
app.use(express.json());: Middleware para analizar cuerpos de solicitudes en formato JSON.

```typescript
app.use("/api", router);
```
app.use("/api", router);: Monta el enrutador principal en la ruta /api. Todas las rutas definidas en el enrutador comenzarán con /api.
```typescript
app.use(errorHandler);
```
app.use(errorHandler);: Aplica el middleware para manejar errores.

4. Arranque del Servidor
```typescript
const startServer = async (): Promise<void> => {
    try {
        await sequelize.authenticate();
        console.log("Connection has been established successfully.");
        await sequelize.sync(); // sync() = Este método sincroniza todos los modelos con la base de datos.
        // await sequelize.sync({force: true}); // force: true = Esta opción indica que Sequelize debe eliminar las tablas existentes y volver a crearlas.
        app.listen(PORT, (): void => {
            console.log(`Server is running on port ${PORT}`);
        });

    } catch (err: any) {
        console.error("There was an error trying to connect the database", err);
    }
}

startServer();
```
const startServer = async (): Promise<void> => {...}: Define una función asíncrona para iniciar el servidor.
await sequelize.authenticate();: Intenta autenticar la conexión a la base de datos.
console.log("Connection has been established successfully.");: Imprime un mensaje si la conexión a la base de datos es exitosa.
await sequelize.sync();: Sincroniza los modelos de Sequelize con la base de datos, asegurando que las tablas existan y estén actualizadas.
app.listen(PORT, (): void => {...});: Inicia el servidor Express en el puerto definido y muestra un mensaje cuando el servidor esté en funcionamiento.
catch (err: any) {...}: Captura y maneja errores durante el proceso de conexión a la base de datos.

Resumen
Este código configura una aplicación Express que:

Configura CORS, JSON parsing, y enrutamiento.
Maneja errores con un middleware específico.
Establece la conexión a la base de datos utilizando Sequelize y sincroniza los modelos.
Inicia el servidor en el puerto especificado, mostrando un mensaje cuando está en funcionamiento.
El enfoque modular y la separación de configuraciones y middleware ayudan a mantener el código organizado y facilitan su mantenimiento.
