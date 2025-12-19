# code
[ScheduledTasksConfig.java](https://github.com/user-attachments/files/24250148/ScheduledTasksConfig.java)
package slowloris_detecter.Config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import slowloris_detecter.Service.IPDetectionService;
import slowloris_detecter.Service.IPAccessCache;
import slowloris_detecter.Mapper.HistoryStatMapper;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.HashMap;

/**
 * 定时任务配置类
 * 实现IP访问统计数据每六小时更新一次的功能
 * 以及实时数据刷新推送功能
 */
@Configuration
@EnableScheduling
public class ScheduledTasksConfig {

    private static final Logger logger = LoggerFactory.getLogger(ScheduledTasksConfig.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Autowired
    private IPAccessCache ipAccessCache;

    @Autowired
    private HistoryStatMapper historyStatMapper;

    @Autowired
    @Lazy
    private IPDetectionService ipDetectionService;

    /**
     * 每六小时执行一次的定时任务
     * 用于更新所有IP的访问统计数据
     */
    @Scheduled(cron = "0 0 */6 * * *")
    public void updateIpAccessStats() {
        logger.info("开始执行IP访问统计数据更新任务，时间: {}", formatter.format(LocalDateTime.now()));

        try {
            // 获取所有缓存的IP访问数据
            Map<String, IPAccessCache.AccessData> allAccessData = ipAccessCache.getAllAccessData();
            
            logger.info("当前缓存中的IP数量: {}", allAccessData.size());
            
            // 遍历所有IP数据并更新到数据库
            for (Map.Entry<String, IPAccessCache.AccessData> entry : allAccessData.entrySet()) {
                String ip = entry.getKey();
                IPAccessCache.AccessData accessData = entry.getValue();
                
                // 构建更新参数
                Map<String, Object> params = new HashMap<>();
                params.put("ip", ip);
                params.put("accessCount", accessData.getAccessCount());
                params.put("normalCount", accessData.getNormalCount());
                params.put("attackCount", accessData.getAttackCount());
                params.put("suspiciousCount", accessData.getSuspiciousCount());
                params.put("status", accessData.getStatus());
                params.put("statTime", LocalDateTime.now());
                params.put("updatedAt", LocalDateTime.now());
                
                // 检查IP是否已存在并执行更新或插入
                if (historyStatMapper.checkIpExists(ip) > 0) {
                    historyStatMapper.updateHistoryStat(params);
                } else {
                    params.put("createdAt", LocalDateTime.now());
                    historyStatMapper.insertHistoryStat(params);
                }
                
                logger.debug("更新IP: {} 的访问统计数据成功", ip);
            }
            
            logger.info("IP访问统计数据更新任务执行完成，时间: {}", formatter.format(LocalDateTime.now()));
            
        } catch (Exception e) {
            logger.error("IP访问统计数据更新任务执行失败: {}", e.getMessage(), e);
        }
    }

}
