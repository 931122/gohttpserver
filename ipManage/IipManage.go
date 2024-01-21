/*
 * @Author: lsjweiyi 759209794@qq.com
 * @Date: 2023-11-21 21:10:44
 * @LastEditors: lsjweiyi 759209794@qq.com
 * @LastEditTime: 2023-11-21 21:13:43
 * @FilePath: \ip-manage\ipManage\iIPManageI.go
 * @Description: ip管理模块的接口
 */
package ipmanage

type IIPManage interface {
	/**
	- @description: 将一个ip 字符串添加到名单里，单线程下添加一千万ip耗时约不到4秒
	- @param {string} ipStr 形如127.0.0.1
	- @return {*}
					0: 输入的ip格式错误
					(0,128): cycleSecond时间内访问次数
					(-128,0):封禁时长
					-128:    永封
	*/
	Add(ipStr string) int8
	/**
	- @description: 增加封禁时长，如果还未被封禁，则等于封禁时长，如果已被封禁，则增加banTime
	- @param {string} ipStr 封禁的IP地址
	- @param {int8} banTime 用负数表示，数值表示增加的时长，单位分钟，-128表示永封
	- @return {int8} 0: 输入的ip格式错误
					(0,128): cycleSecond时间内访问次数
					(-128,0):封禁时长
					-128:    永封
	*/
	AddBanTime(ipStr string, banTime int8) int8 // 给一个ip增加封禁时长
	/**
	 * @description: 判断一个ip是否被封禁，如果被封禁，则返回封禁时长，否则返回访问次数
	 * @param {string} ipStr
	 * @return {int8} 第一个返回值的含义：0：表示该ip未记录；>0:表示该ip的访问次数；<0:表示该ip的封禁时长；-128：表示该ip永久封禁
			   {bool} 第二个返回值的含义：false:输入的ip有误,true:输入的ip正确
	*/
	IsBan(ipStr string) (int8, bool) // 判断一个ip是否被禁用
	GetLen() int                     //获取黑名单列表长度
	GetAll() []string                // 获取黑名单列表，升序排序
	GetSizeOf() uintptr              // 获取黑名单列表占用的内存空间
}
