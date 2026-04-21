import { expressjwt as jwt } from 'express-jwt';
import config from '../config.json';
import db from '../_helpers/db';

const { secret } = config;

export default function authorize(roles: any = []) {
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return [
       
        jwt({ secret, algorithms: ['HS256'] }),

        async (req: any, res: any, next: any) => {
          
            if (!req.auth) return res.status(401).json({ message: 'Unauthorized' });

            const account = await db.Account.findByPk(req.auth.id);

            if (!account || (roles.length && !roles.includes(account.role))) {
                return res.status(401).json({ message: 'Unauthorized' });
            }

            req.user = account; 
            req.user.role = account.role;
            
            const refreshTokens = await account.getRefreshTokens();
            req.user.ownsToken = (token: any) => !!refreshTokens.find((x: any) => x.token === token);
            
            next();
        }
    ];
}