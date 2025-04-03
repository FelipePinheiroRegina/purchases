import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Request } from 'express'
import {
  auth,
  type AuthOptions,
  type AuthResult,
} from 'express-oauth2-jwt-bearer'

export const jwtVerifier = (config?: Omit<AuthOptions, 'authRequired'>) => {
  const middleware = auth(config)

  return (accessToken?: string): Promise<AuthResult> => {
    return new Promise((resolve, reject) => {
      const request = {
        query: { access_token: accessToken },
        headers: {},
        is: () => false,
        auth: undefined as unknown as AuthResult,
      }

      void middleware(request as any, {} as any, (error: unknown) => {
        if (error) {
          reject(
            error instanceof Error
              ? error
              : new Error(JSON.stringify(error, null, 2)),
          )
        } else {
          resolve(request.auth)
        }
      })
    })
  }
}
@Injectable()
export class AuthorizationGuard implements CanActivate {
  private AUTH0_AUDIENCE: string
  private AUTH0_DOMAIN: string

  constructor(private configService: ConfigService) {
    this.AUTH0_AUDIENCE = this.configService.get('AUTH0_AUDIENCE') ?? ''
    this.AUTH0_DOMAIN = this.configService.get('AUTH0_DOMAIN') ?? ''
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const httpContext = context.switchToHttp()
    const req = httpContext.getRequest<Request>()

    const jwtCheck = jwtVerifier({
      audience: this.AUTH0_AUDIENCE,
      issuerBaseURL: this.AUTH0_DOMAIN,
      tokenSigningAlg: 'RS256',
    })

    const token = req.headers.authorization?.split(' ')[1]

    try {
      await jwtCheck(token)
      return true
    } catch (err) {
      throw new UnauthorizedException(err)
    }
  }
}
