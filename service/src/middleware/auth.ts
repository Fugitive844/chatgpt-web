import jwt from 'jsonwebtoken'
import type { Request } from 'express'
import { getCacheConfig } from '../storage/config'
import { getUserById } from '../storage/mongo'
import { Status } from '../storage/model'
import type { AuthJwtPayload } from '../types'
export const tokenMap = new Map<string, any>()

async function auth(req, res, next) {
  const config = await getCacheConfig()
  if (config.siteConfig.loginEnabled) {
    try {
      const token = req.header('Authorization').replace('Bearer ', '')
      const info = jwt.verify(token, config.siteConfig.loginSalt.trim()) as AuthJwtPayload
      req.headers.userId = info.userId
      
      //自定义权限认证
      let userId = info.userId.toString()
      let mytoken = tokenMap.get(userId) 
      let timestamp2 = tokenMap.get(userId+"time") 
      const now = Date.now();
     tokenMap.set(userId+"time",Date.now())
     const seconds = ( now - timestamp2)/1000/60;
    //  let logoutMin = process.env.LOGOUT_MIN;
     let logoutMin = parseInt(process.env.LOGOUT_MIN, 30); // 将环境变量转换为整数类型

     if(logoutMin == null){
         logoutMin= 30
     }
     if(seconds>logoutMin){
         console.log("长时间未登录，token已过期")
         res.send({ status: 'Unauthorized', message: "长时间未登录，token已过期" ?? 'Please authenticate.', data: null })

         return
     }
      
      if(mytoken==null || mytoken !== token){
          console.log("本地缓存未查询到token")
          res.send({ status: 'Unauthorized', message: "本地缓存未查询到token" ?? 'Please authenticate.', data: null })

          return
      }
      next()
      //自定义权限认证
    }
    catch (error) {
      res.send({ status: 'Unauthorized', message: error.message ?? 'Please authenticate.', data: null })
    }
  }
  else {
    // fake userid
    req.headers.userId = '6406d8c50aedd633885fa16f'
    next()
  }
}

async function getUserId(req: Request): Promise<string | undefined> {
  let token: string
  try {
    token = req.header('Authorization').replace('Bearer ', '')
    const config = await getCacheConfig()
    const info = jwt.verify(token, config.siteConfig.loginSalt.trim()) as AuthJwtPayload
    return info.userId
  }
  catch (error) {
    globalThis.console.error(`auth middleware getUserId err from token ${token} `, error.message)
  }
  return null
}

export { auth, getUserId }
