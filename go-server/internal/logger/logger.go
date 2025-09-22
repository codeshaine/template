package logger

import (
	l "log"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func Init() *zap.Logger {

	env := viper.GetString("server.env")

	if env == "prod" {

		logFile := &lumberjack.Logger{
			Filename:   viper.GetString("logs.file"),
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     30,
			Compress:   true,
		}

		cfg := zap.NewProductionEncoderConfig()
		core := zapcore.NewCore(
			zapcore.NewJSONEncoder(cfg),
			zapcore.AddSync(logFile),
			zap.InfoLevel,
		)
		logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.WarnLevel))

		zap.ReplaceGlobals(logger)

		zap.S().Infow("logger set up successfully", "key", "value")

		return logger

	}

	if env == "dev" {
		logFile := &lumberjack.Logger{
			Filename:   viper.GetString("logs.file"),
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     30,
			Compress:   true,
		}

		cfg := zap.NewDevelopmentEncoderConfig()
		core := zapcore.NewCore(
			zapcore.NewJSONEncoder(cfg),
			zapcore.AddSync(logFile),
			zap.DebugLevel,
		)
		logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.DebugLevel))

		zap.ReplaceGlobals(logger)

		zap.S().Infow("logger set up successfully", "key", "value")

		return logger

	}

	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	logger, err := cfg.Build()
	if err != nil {
		l.Fatalln("logger build", err)
	}

	zap.ReplaceGlobals(logger)

	logger.Debug("logger set up")

	return logger

}

var log *zap.Logger

func init() {
	var err error

	config := zap.NewProductionConfig()

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.StacktraceKey = ""
	config.EncoderConfig = encoderConfig

	log, err = config.Build(zap.AddCallerSkip(1))

	if err != nil {
		panic(err)
	}
}

func Info(message string, fields ...zap.Field) {
	log.Info(message, fields...)
}

func Fatal(message string, fields ...zap.Field) {
	log.Fatal(message, fields...)
}

func Debug(message string, fields ...zap.Field) {
	log.Debug(message, fields...)
}

func Error(message string, fields ...zap.Field) {
	log.Error(message, fields...)
}
