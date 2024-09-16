import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import dotenv from 'dotenv';
dotenv.config();

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Task Management API',
            version: '1.0.0',
            description: 'Task Management API',
        },
        servers: [
            {
                url: process.env.URL,
            }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                },
            },
            schemas: {
                Task: {
                    type: 'object',
                    properties: {
                        id: {
                            type: 'string',
                            description: 'The auto-generated id of the task'
                        },
                        title: {
                            type: 'string',
                            description: 'The title of the task'
                        },
                        description: {
                            type: 'string',
                            description: 'The description of the task'
                        },
                        completed: {
                            type: 'boolean',
                            description: 'The completion status of the task'
                        },
                    },
                    required: ['title', 'description']
                },
                User: {
                    type: 'object',
                    properties: {
                        id: {
                            type: 'string',
                            description: 'The auto-generated id of the user'
                        },
                        email: {
                            type: 'string',
                            description: 'email'
                        },
                        password: {
                            type: 'string',
                            description: 'password'
                        }
                    },
                    required: ['email', 'password']
                },
            },
        },
    },
    apis: ['./routes/*.js'],
};

const specs = swaggerJsdoc(options);

export default (app) => {
    
    const swaggerOptions = {
        swaggerOptions: {
            plugins: [
                {
                    security: {
                        bearerAuth: [],
                    },
                },
            ],
        },
    };

    app.use('/swagger', swaggerUi.serve, swaggerUi.setup(specs, swaggerOptions));
};
