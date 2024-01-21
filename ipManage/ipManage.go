/*
 * @Author: lsjweiyi 759209794@qq.com
 * @Date: 2023-11-13 19:23:17
 * @LastEditors: lsjweiyi 759209794@qq.com
 * @LastEditTime: 2023-11-21 21:14:00
 * @FilePath: \ip-black\blackList\onlyIp\ipStru.go
 * @Description: ip管理模块的实现
 */
package ipmanage

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// 访问ip管理
type ipVisitS struct {
	// 黑名单列表，正好对应ip地址的四层，以下标计数，-1表示永久封禁
	// int8 既可计数，又可表达状态其中，每访问一次，次数加1，当次数累计达到多少时，则可以标记状态
	// 状态的表示使用负数，因为取值范围是[-128,127],所以规定：-128表示永久封禁用户，剩余的负数表示临时封禁的时长，单位分钟
	// 有定时任务每cycleSecond循环检查一次，当取值范围为[-127,0)时，加1，表示封禁时长减一分钟。当取值范围为(0,127]时，归零，表示封禁时长减一分钟
	// 应对场景，防止恶意高频访问。不需要应对非常精确的场景，优点，简单，节省内存，速度非常快，比基于redis的更快，因为没有通信消耗。
	// 方案弊端：1. 按分钟计算，每分钟都得做一次循环，占用性能
	// 2. 封禁时长不可超过127分钟，超过127分钟，将无法计算，只能升级为永封
	// 3. 访问次数每分钟上限限制在127次，再往上无法计算了const
	// 4. 无法记录每次访问的时间，每次巡查只能直接清零
	// 5. 无法记录封禁原因
	// 6. 无法精准的执行封禁时间，因为每次循环本身就需要执行时间，这个执行时间是不计算进封禁时间的
	IpList            [256]*[256]*[256]*[256]int8
	limit             int8  // 设置的每cycleSecond的访问上限
	cycleSecond       int32 // 每次循环检查的间隔时长，单位秒
	visitLimitBanTime int8  // 访问超限的封禁时长，单位分钟
}

/**
 * @description: 初始化
 * @param {int8} limit 设置的每cycleSecond的访问上限
 * @param {int32} cycleSecond 每次循环检查的间隔时长，单位秒
 * @param {int8} visitLimitBanTime 访问超限的封禁时长，单位分钟
 * @return {*ipVisitS} 对象
 * @return {error} 错误
 */
func InitIpVisit(limit int8, cycleSecond int32, visitLimitBanTime int8,stopChan chan bool) (*ipVisitS, error) {
	if !(limit >= 0 && limit <= 127) {
		return nil, errors.New("limit的取值范围是 [0,127]")
	} else if !(cycleSecond >= 1 && cycleSecond <= 3600) {
		return nil, errors.New("cycleSecond的取值范围是 [1,3600]秒")
	} else if !(visitLimitBanTime >= 1 && visitLimitBanTime <= 127) {
		return nil, errors.New("visitLimitBanTime的取值范围是 [1,127]分钟")
	}

	ipVisit := &ipVisitS{
		limit:             limit,
		cycleSecond:       cycleSecond,
		visitLimitBanTime: visitLimitBanTime,
	}
	ipVisit.CheckIPList(stopChan) // 启动定时器
	return ipVisit, nil
}

/*
*
  - @description: 将一个ip 字符串添加到黑名单里，单线程下添加5千万ip耗时约20秒
  - @param {string} ipStr 形如127.0.0.1
  - @return {*} 
    0: 输入的ip格式错误
    (0,128): cycleSecond时间内访问次数
	(-128,0):封禁时长
    -128:    永封
*/
func (i *ipVisitS) Add(ipStr string) int8 {
	ipIntList, errCode := splitIp(ipStr)
	if errCode != 0 {
		return 0
	}

	thisIP := i.nil2Create(ipIntList)
	// 前面都是初始化的校验，下面才是记录ip
	if thisIP[ipIntList[3]] < 0 { // 小于零说明已经被封禁
		return thisIP[ipIntList[3]]
	} else if thisIP[ipIntList[3]] >= 0 && thisIP[ipIntList[3]] < i.limit {
		thisIP[ipIntList[3]] ++ // 访问次数加1
	} else if thisIP[ipIntList[3]] == i.limit { // 访问达到上限，封禁一定时间
		thisIP[ipIntList[3]] = -(i.visitLimitBanTime)
	}
	return thisIP[ipIntList[3]]
}

/*
*
  - @description: 增加封禁时长，如果还未被封禁，则等于封禁时长，如果已被封禁，则增加banTime
  - @param {string} ipStr 封禁的IP地址
  - @param {int8} banTime 用负数表示，数值表示增加的时长，单位分钟，-128表示永封
  - @return {int8}     0: 输入的ip格式错误
    (0,128): cycleSecond时间内访问次数
	(-128,0):封禁时长
    -128:    永封
*/
func (i *ipVisitS) AddBanTime(ipStr string, banTime int8) int8 {
	ipIntList, errCode := splitIp(ipStr)
	if errCode != 0 {
		return 0
	}
	thisIP := i.nil2Create(ipIntList)
	// 前面都是初始化的校验，下面才是记录ip
	if banTime == -128 { // 表示永封
		thisIP[ipIntList[3]] = banTime
	} else {
		if thisIP[ipIntList[3]] >= 0 { // 大于等于零说明还未被封禁
			thisIP[ipIntList[3]] = banTime
		} else if thisIP[ipIntList[3]] < 0 { // 小于零需要判断它再加上banTime会不会达到-128
			if thisIP[ipIntList[3]]+banTime > -128 {
				thisIP[ipIntList[3]] += banTime
			} else {
				thisIP[ipIntList[3]] = -127 // 如果会，使其等于-127，因为增加封禁时长不能让其永封
			}
		}
	}
	return thisIP[ipIntList[3]]
}

/**
 * @description: 判断一个ip是否被封禁，如果被封禁，则返回封禁时长，否则返回访问次数
 * @param {string} ipStr
 * @return {int8} 第一个返回值的含义：0：表示该ip未记录；>0:表示该ip的访问次数；<0:表示该ip的封禁时长；-128：表示该ip永久封禁
		   {bool} 第二个返回值的含义：false:输入的ip有误,true:输入的ip正确
 */
func (i *ipVisitS) IsBan(ipStr string) (int8,bool) {
	ipIntList, errCode := splitIp(ipStr)
	if errCode != 0 {
		return 0,false
	}
	if i.IpList[ipIntList[0]] == nil || i.IpList[ipIntList[0]][ipIntList[1]] == nil || i.IpList[ipIntList[0]][ipIntList[1]][ipIntList[2]] == nil {
		return 0,true
	}
	return i.IpList[ipIntList[0]][ipIntList[1]][ipIntList[2]][ipIntList[3]],true
}

/**
 * @description: 检查ip是否为空值，如果是，则创建该ip,最后一位的值不设置，需要后续代码自己设置值
 * @param {[]int} []int ip数组
 * @return {*}
 */
func (i *ipVisitS) nil2Create(ipIntList []int) *[256]int8 {
	// 这里是ip的第二层，为空时就初始化
	if i.IpList[ipIntList[0]] == nil {
		var a [256]*[256]*[256]int8 // 每个位置都对应256个数字，直接初始化256个位置
		var b [256]*[256]int8
		var c [256]int8

		a[ipIntList[1]] = &b
		b[ipIntList[2]] = &c

		i.IpList[ipIntList[0]] = &a
	} else if i.IpList[ipIntList[0]][ipIntList[1]] == nil { // 这里是ip的第三层，为空时就初始化
		// var a [256]*[4]int64
		var b [256]*[256]int8 // 每个位置都对应256个数字，直接初始化256个位置
		var c [256]int8
		b[ipIntList[2]] = &c
		i.IpList[ipIntList[0]][ipIntList[1]] = &b
	} else if i.IpList[ipIntList[0]][ipIntList[1]][ipIntList[2]] == nil { // 这里是ip的第四层，为空时就初始化
		// int64就是64bit，第N个bit就可以代表第N个数字，256/4就是4，将[]int64看成是一个连续的存储空间，所以长度为4的int64数组就可以表示256位数
		var c [256]int8
		i.IpList[ipIntList[0]][ipIntList[1]][ipIntList[2]] = &c
	}
	return i.IpList[ipIntList[0]][ipIntList[1]][ipIntList[2]]
}

/**
 * @description: 将ip字符串分割成ip数组
 * @param {string} ipStr ip字符串
 * @return {*} ip数组和错误码，-1表示ip格式错误，否则为0
 */
func splitIp(ipStr string) ([]int, int8) {
	ipSplit := strings.Split(ipStr, ".")
	if len(ipSplit) != 4 {
		return nil, -1
	}
	// 转整形
	ipIntList := make([]int, 4)
	for i := 0; i < 4; i++ {
		a, err := strconv.Atoi(ipSplit[i])
		if err != nil {
			return nil, -1
		}
		if a > 255 || a < 0 {
			return nil, -1
		}
		ipIntList[i] = a
	}
	if ipIntList[3] == 0 { // ip的最后一位不可以为0
		return nil, -1
	}
	return ipIntList, 0
}

/**
 * @description: 获取黑名单列表长度
 * @return {*}
 */
func (i *ipVisitS) GetLen() (listLen int) {
	listLen, _ = i.get(1)
	return
}

/**
 * @description: 获取所有的ip，也就是层层判断数组的哪些值不为空，此时的下标就表示一个值，这种方式下还顺便做了升序排序
 * @return {*}
 */
func (i *ipVisitS) GetAll() (ipList []string) {
	_, ipList = i.get(2)
	return
}

/**
 * @description: 获取黑名单长度或者黑名单列表
 * @param {int} getType 1：获取长度；2：获取黑名单列表
 * @return {*}
 */
func (ip *ipVisitS) get(getType int) (listLen int, ipStrList []string) {
	for i := 0; i < 256; i++ {
		if ip.IpList[i] == nil {
			continue
		}
		for j := 0; j < 256; j++ {
			if ip.IpList[i][j] == nil {
				continue
			}
			for k := 0; k < 256; k++ {
				if ip.IpList[i][j][k] == nil {
					continue
				}
				for l := 0; l < 256; l++ {
					if ip.IpList[i][j][k][l] == 0 {
						continue
					}
					// 仅统计数量
					if getType == 1 {
						listLen ++
					} else {
						// 生成ip
						ipStrList = append(ipStrList, fmt.Sprintf("%d.%d.%d.%d", i, j, k, l))
					}
				}

			}
		}
	}
	return
}

/**
 * @description: 获取黑名单当前所占的内存
 * @return {*} 字节数
 */
func (ip *ipVisitS) GetSizeOf() uintptr {
	var size uintptr
	size = unsafe.Sizeof(ip.IpList) // 只能获取第一层的数组的内存，后续关联的指针所指向的内存是无法获取的
	// 后续层层查询占用的内存，相加
	for i := 0; i < 256; i++ {
		size += unsafe.Sizeof(ip.IpList[i])
		if ip.IpList[i] == nil {
			continue
		}
		for j := 0; j < 256; j++ {
			size += unsafe.Sizeof(ip.IpList[i][j])
			if ip.IpList[i][j] == nil {
				continue
			}
			for k := 0; k < 256; k++ {
				size += unsafe.Sizeof(ip.IpList[i][j][k])
				if ip.IpList[i][j][k] == nil {
					continue
				}
				size += unsafe.Sizeof(ip.IpList[i][j][k][0]) * 256 // 每一位大小都一样的，所以乘以256即可
			}
		}
	}
	return size
}

// 定时任务,每cycleSecond循环检查一次，当取值范围为[-127,0)时，加1，表示封禁时长减一分钟。当取值范围为(0,127]时，归零，表示封禁时长减一分钟
/**
 * @description: 定时任务,每cycleSecond循环检查一次，当取值范围为[-127,0)时，加1，表示封禁时长减一分钟。当取值范围为(0,127]时，归零，表示访问次数清零。且将不再记录ip段重置为空值，防止一直占用内存
 * @param {chanbool} stopChan 程序外部的输入信号，用于告知协程的无限循环该终止了。定时器stop并不会关闭他们所在的协程，需要额外使用StopChan发出关闭协程的信号
 * @return {*} *time.Ticker
 */
func (ip *ipVisitS) CheckIPList(stopChan chan bool) *time.Ticker {
	ticker := time.NewTicker(time.Second*time.Duration(ip.cycleSecond))
	go func() {
		for {
			select {
			case <-ticker.C:
				// 一下变量记录每一层是否有记录ip,如果都没有记录ip,，则将引用置空，防止一直占用内存
				second := 0
				third := 0
				fourth := 0
				for i := 0; i < 256; i++ {
					if ip.IpList[i] == nil {
						continue
					}
					second = 0 // 进入该段的循环前，清空前面记录的次数
					for j := 0; j < 256; j++ {
						if ip.IpList[i][j] == nil {
							continue
						}
						third = 0 // 进入该段的循环前，清空前面记录的次数
						for k := 0; k < 256; k++ {
							if ip.IpList[i][j][k] == nil {
								continue
							}
							fourth = 0 // 进入该段的循环前，清空前面记录的次数
							for l := 0; l < 256; l++ {
								if ip.IpList[i][j][k][l] == 0 {
									continue
								}
								// 表明该断内记录了ip
								fourth++
								third++
								second++

								// 永封的不处理
								if ip.IpList[i][j][k][l] == -128 {
									continue
								} else if ip.IpList[i][j][k][l] > 0 {
									ip.IpList[i][j][k][l]--
								} else if ip.IpList[i][j][k][l] < 0 {
									ip.IpList[i][j][k][l]++
								}
							}
							// 如果第四层循环结束还是为0，表明该段没有记录ip，可以置空回收，当然，访问次数或封禁时间刚恢复到0的不包含在内
							if fourth == 0 {
								ip.IpList[i][j][k] = nil
							}
						}
						// 如果第三层循环结束还是为0，表明该段没有记录ip
						if third == 0 {
							ip.IpList[i][j] = nil
						}
					}
					// 如果第二层循环结束还是为0，表明该段没有记录ip
					if second == 0 {
						ip.IpList[i] = nil
					}
				}
			case <-stopChan:
				return // 退出协程
			}
		}
	}()
	return ticker
}
