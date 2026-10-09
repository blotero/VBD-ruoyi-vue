package com.ruoyi.framework.security.handle;

import java.util.TimerTask;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.framework.manager.AsyncManager;
import com.ruoyi.framework.web.service.TokenService;

/**
 * 退出时清理用户令牌
 * @author ruoyi
 */
@Component
public class TokenLogoutHandler implements LogoutHandler
{
    private static final Logger log = LoggerFactory.getLogger(TokenLogoutHandler.class);

    @Autowired
    private TokenService tokenService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
    {
        LoginUser loginUser = tokenService.getLoginUser(request);
        if (StringUtils.isNull(loginUser))
        {
            return;
        }
        AsyncManager.me().execute(new TimerTask()
        {
            @Override
            public void run()
            {
                try
                {
                    tokenService.delLoginUser(loginUser.getToken());
                }
                catch (Exception e)
                {
                    log.warn("清理用户[{}]令牌异常'{}'", loginUser.getUsername(), e.getMessage());
                }
            }
        });
    }
}
