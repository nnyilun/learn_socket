# 预期

1 监听用户连接，用户连接后分配用户至登陆线程

2 用户登陆之后，连接至全局聊天

3 使用/send <username> message  发送消息到指定用户

4 用户可以创建聊天室，其他人可以申请加入聊天室或者邀请他人加入

线程会话为<int, std::pair<std::thread, int>>类型，第一个int表示聊天室拥有者FD，后面的表示聊天室线程及状态