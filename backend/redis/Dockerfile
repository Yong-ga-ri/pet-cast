# 베이스 이미지 설정
FROM redis:alpine

# Redis 설정 파일 복사 (필요한 경우)
COPY ./redis.conf /usr/local/etc/redis/redis.conf

# Redis 시작 시 커스텀 설정을 적용하여 실행
CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]