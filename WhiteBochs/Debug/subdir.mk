################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../concrete-whitebochs.o \
../concrete-whitedisasm.o \
../fuzzball-whitebochs.o \
../fuzzball-whitedisasm.o \
../symbolic.o 

C_SRCS += \
../run-on-cpu.c 

CC_SRCS += \
../symbolic.cc \
../test-cache.cc \
../whitebochs.cc \
../whitedisasm.cc 

OBJS += \
./run-on-cpu.o \
./symbolic.o \
./test-cache.o \
./whitebochs.o \
./whitedisasm.o 

C_DEPS += \
./run-on-cpu.d 

CC_DEPS += \
./symbolic.d \
./test-cache.d \
./whitebochs.d \
./whitedisasm.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

%.o: ../%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


