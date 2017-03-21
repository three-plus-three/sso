package sso

// 客户端代码中 client 包中
// 服务端代码中 server 包中

// 1. 拦载所有请求， 看是否已登录， 如果已登录，则继续，否则进入下一步
// 2. 取 query 参数(名为 ticket), 如果不为空则进入第 4 步
// 3. 重定向到  /hengwei/sso/login?service=zzzzzzz， 注意 zzzzzzz 是你当前的 url
// 3. 登录界面在用户登录成功后会重定向到 zzzzzzz 页面，同时会在 query 参数中加入一个 ticket=ST-XXXXXX
// 4. 向 /hengwei/sso/verify?ticket=ST-XXXXXX 发送请求，确认 ticket 是否有效，如果无效转到第三步，否则进入下一步
// 5. 在当前会话中增加一个已登录标记
// 6. 验证已完成， 继续下一步

// 如何判断是否已登录？
// PlayFramework 是支持 session 的，在session中增加一个 key 名为 _valid  的 boolean 值，没有值 或 false 表示未登录， true 表示已登录，

// 如何与其它程序共用一个 session,
// PlayFramework 的 session 是存在一个名为 PLAY_SESSION 的 cookie 中， 这个 cookie 是一个用 urlquery 方式编码的 map<string, string>, 它有下列值

// session_id 会话的唯一标识
// user 用户名

// 我们可以在增加一些值，如下
// _valid 是否已登录，boolean 值， 没有值 或 false 表示未登录， true 表示已登录，
// _expire 过期时间，它是 int 型， 为 unix 时间

// 你可能会有下列疑问
// 1. cookie 本身有过期时间，为什么不直接用，而用加了一个 _expire 字段？
// 答： cookie 可以被人嗅探拷贝后，一直使用，人为的让它永远不过期。
// 2. 可不可以用 PLAY_SESSION 的 cookie 值不为空来判断是否已登录
// 答： 答案同上。
// 3. cookie 是明文的，用户可不可以伪造一个 PLAY_SESSION 的 cookie 值呢？
// 答：cookie 是可以伪造的，但不起效，PLAY_SESSION 的 cookie 值分成两部分，1. 数据， 2. 签名
//     PlayFramework 会将数据用 hash 加盐算法生成一个签名，然后与上面的签名作对比，看 cookie 是
//     否被更改。
