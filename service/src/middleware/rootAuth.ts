import jwt from 'jsonwebtoken'
import * as dotenv from 'dotenv'
import { Status, UserRole } from '../storage/model'
import { getUserById } from '../storage/mongo'
import { getCacheConfig } from '../storage/config'
import type { AuthJwtPayload } from '../types'
import { tokenMap } from './auth'

dotenv.config()

async function rootAuth(req, res, next) {
  const config = await getCacheConfig()
  if (config.siteConfig.loginEnabled) {
    try {
      const token = req.header('Authorization').replace('Bearer ', '')
      const info = jwt.verify(token, config.siteConfig.loginSalt.trim()) as AuthJwtPayload
      req.headers.userId = info.userId
      const user = await getUserById(info.userId)
      if (user == null || user.status !== Status.Normal || !user.roles.includes(UserRole.Admin)){
        res.send({ status: 'Fail', message: '无权限 | No permission.', data: null })
        return
      }
      //自定义权限认证
      let userId = info.userId.toString()
      let mytoken = tokenMap.get(userId)
      let timestamp2 = tokenMap.get(userId+"time")
      const now = Date.now();
     tokenMap.set(userId+"time",Date.now())
     const seconds = ( now - timestamp2)/1000/60;
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
      if(!info.root){
         console.log("当前用户非管理用户,无法调用管理员接口")
         res.send({ status: 'Fail', message: '无权限 | No permission.', data: null })
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
    res.send({ status: 'Fail', message: '无权限 | No permission.', data: null })
  }
}

async function isAdmin(userId: string) {
  const user = await getUserById(userId)
  return user != null && user.status === Status.Normal && user.roles.includes(UserRole.Admin)
}

export { rootAuth, isAdmin }
