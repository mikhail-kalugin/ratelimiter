package ratelimiter

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

type RateLimiter struct {
	// Клиент Redis
	redisClient *redis.Client
	// Скользящее окно – период времени, за который будет отслеживаться количество запросов (например, 1 минута)
	windowSize time.Duration
	// Максимальное количество запросов в окне
	maxRequests int
	// Префикс для ключей Redis (например, "ratelimit:")
	keyPrefix string
}

func New(redisClient *redis.Client, windowSize time.Duration, maxRequests int, keyPrefix string) *RateLimiter {
	return &RateLimiter{
		redisClient: redisClient,
		windowSize:  windowSize,
		maxRequests: maxRequests,
		keyPrefix:   keyPrefix,
	}
}

// formatKey форматирует ключ Redis с префиксом
func (r *RateLimiter) formatKey(key string) string {
	return fmt.Sprintf("%s%s", r.keyPrefix, key)
}

// Allow проверяет, не превышен ли лимит запросов для данного ключа
func (r *RateLimiter) Allow(key string) bool {
	return r.AllowWithContext(context.Background(), key)
}

// AllowWithContext тоже что и Allow, но с поддержкой контекста
func (r *RateLimiter) AllowWithContext(ctx context.Context, key string) bool {
	redisKey := r.formatKey(key)
	now := time.Now().UnixNano()
	windowStart := now - r.windowSize.Nanoseconds()

	luaScript := `
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local windowStart = tonumber(ARGV[2])
        local maxRequests = tonumber(ARGV[3])
        local ttl = tonumber(ARGV[4])
        
        -- Удаляем все записи старше окна (очистка старых записей)
        redis.call('ZREMRANGEBYSCORE', key, 0, windowStart)
        
        -- Получаем количество запросов в текущем окне
        local count = redis.call('ZCARD', key)
        
        -- Проверяем, можем ли мы добавить еще один запрос
        if count >= maxRequests then
            return {count, 0}  -- Превышен лимит
        end
        
        -- Добавляем текущий запрос в отсортированный набор с меткой времени
        redis.call('ZADD', key, now, now .. '-' .. math.random())
        
        -- Устанавливаем TTL для автоматической очистки
        redis.call('EXPIRE', key, ttl)
        
        -- Возвращаем количество запросов и флаг допустимости
        return {count + 1, 1}
    `

	res, err := r.redisClient.Eval(
		ctx,
		luaScript,
		[]string{redisKey},
		now,
		windowStart,
		r.maxRequests,
		int(r.windowSize.Seconds()),
	).Result()

	// Если произошла ошибка Redis, запрещаем запрос для безопасности
	if err != nil {
		return false
	}

	results, ok := res.([]interface{})
	if !ok || len(results) != 2 {
		return false
	}

	allowed, ok := results[1].(int64)
	if !ok {
		return false
	}

	return allowed == 1
}

// Reset сбрасывает счетчик для указанного ключа
func (r *RateLimiter) Reset(key string) error {
	return r.ResetWithContext(context.Background(), key)
}

// ResetWithContext сбрасывает счетчик с поддержкой контекста
func (r *RateLimiter) ResetWithContext(ctx context.Context, key string) error {
	redisKey := r.formatKey(key)
	return r.redisClient.Del(ctx, redisKey).Err()
}

// Remaining возвращает количество оставшихся запросов для ключа
func (r *RateLimiter) Remaining(key string) (int, error) {
	return r.RemainingWithContext(context.Background(), key)
}

// RemainingWithContext возвращает количество оставшихся запросов с поддержкой контекста
func (r *RateLimiter) RemainingWithContext(ctx context.Context, key string) (int, error) {
	redisKey := r.formatKey(key)
	now := time.Now().UnixNano()
	windowStart := now - r.windowSize.Nanoseconds()

	luaScript := `
		local key = KEYS[1]
		local windowStart = tonumber(ARGV[1])
		local maxRequests = tonumber(ARGV[2])
		
		-- Удаляем старые записи
		redis.call('ZREMRANGEBYSCORE', key, 0, windowStart)
		
		-- Получаем текущее количество
		local currentCount = redis.call('ZCARD', key)
		
		-- Возвращаем оставшееся количество (не меньше 0)
		local remaining = maxRequests - currentCount
		return remaining > 0 and remaining or 0
	`

	res, err := r.redisClient.Eval(
		ctx,
		luaScript,
		[]string{redisKey},
		windowStart,
		r.maxRequests,
	).Result()

	if err != nil {
		return 0, err
	}

	remaining, ok := res.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected result type")
	}

	return int(remaining), nil
}

// WhenAvailable возвращает время, через которое лимит будет доступен
func (r *RateLimiter) WhenAvailable(key string) (time.Duration, error) {
	return r.WhenAvailableWithContext(context.Background(), key)
}

// WhenAvailableWithContext возвращает время до доступности с поддержкой контекста
func (r *RateLimiter) WhenAvailableWithContext(ctx context.Context, key string) (time.Duration, error) {
	redisKey := r.formatKey(key)
	now := time.Now().UnixNano()
	windowStart := now - r.windowSize.Nanoseconds()

	luaScript := `
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local windowStart = tonumber(ARGV[2])
		local maxRequests = tonumber(ARGV[3])
		
		-- Удаляем старые записи
		redis.call('ZREMRANGEBYSCORE', key, 0, windowStart)
		
		-- Получаем текущее количество
		local currentCount = redis.call('ZCARD', key)
		
		-- Если еще есть доступные запросы, возвращаем 0
		if currentCount < maxRequests then
			return 0
		end
		
		-- Получаем самую старую запись
		local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
		if not oldest or #oldest < 2 then
			return 0
		end
		
		-- Рассчитываем, когда самая старая запись выйдет за пределы окна
		local oldestTime = tonumber(oldest[2])
		local waitTime = oldestTime - windowStart
		
		-- Возвращаем время ожидания в наносекундах
		return waitTime > 0 and waitTime or 0
	`

	res, err := r.redisClient.Eval(
		ctx,
		luaScript,
		[]string{redisKey},
		now,
		windowStart,
		r.maxRequests,
	).Result()

	if err != nil {
		return 0, err
	}

	waitTimeNano, ok := res.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected result type")
	}

	return time.Duration(waitTimeNano), nil
}
