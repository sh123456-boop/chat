package com.ktb.community.chat.config;

import com.ktb.community.chat.service.ChatServiceImpl;
import com.ktb.community.exception.BusinessException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static com.ktb.community.exception.ErrorCode.ACCESS_DENIED;
import static com.ktb.community.exception.ErrorCode.ROOM_NOT_FOUND;

@Component
public class StompHandler implements ChannelInterceptor {

    private SecretKey secretKey;

    private final ChatServiceImpl chatServiceImpl;

    public StompHandler(@Value("${jwt.secret}") String secret, ChatServiceImpl chatServiceImpl) {

        // yml 파일 기반 secret 키 생성
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
        this.chatServiceImpl = chatServiceImpl;
    }

    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        final StompHeaderAccessor accessor = StompHeaderAccessor.wrap(message);
        // Ws 연결시 토큰 검증
        if (StompCommand.CONNECT == accessor.getCommand()){
            String accessToken = accessor.getFirstNativeHeader("access");
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(accessToken)
                    .getPayload().get("userId", Long.class);
            System.out.println("----------------------------------------------");
            System.out.println("StompCommand.CONNECT 성공");
            System.out.println("----------------------------------------------");
        }
        // 특정 방 구독 시 접근 권한 확인
        if (StompCommand.SUBSCRIBE == accessor.getCommand()) {
            String accessToken = accessor.getFirstNativeHeader("access");
            Long userId = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(accessToken)
                    .getPayload().get("userId", Long.class);

            String[] segments = accessor.getDestination().split("/");
            if (segments.length < 4) {
                throw new BusinessException(ROOM_NOT_FOUND);
            }
            Long roomId = Long.parseLong(segments[4]);


            if(!chatServiceImpl.isRoomParticipant(userId, roomId)){
                throw new BusinessException(ACCESS_DENIED);
            }
            System.out.println("----------------------------------------------");
            System.out.println("StompCommand.SUBSCRIBE 성공");
            System.out.println("----------------------------------------------");
        }
        return message;
    }
}
