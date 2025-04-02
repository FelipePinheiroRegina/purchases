import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { NextFunction, Response, Request } from 'express'
import { auth } from 'express-oauth2-jwt-bearer'

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
    const res = httpContext.getResponse<Response>()
    const next = httpContext.getNext<NextFunction>()

    const jwtCheck = auth({
      audience: this.AUTH0_AUDIENCE,
      issuerBaseURL: this.AUTH0_DOMAIN,
      tokenSigningAlg: 'RS256',
    })

    try {
      await jwtCheck(req, res, next)
      return true
    } catch (err) {
      throw new UnauthorizedException(err)
    }
  }
}
