################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../fpu/f2xm1.o \
../fpu/ferr.o \
../fpu/fpatan.o \
../fpu/fprem.o \
../fpu/fpu.o \
../fpu/fpu_arith.o \
../fpu/fpu_compare.o \
../fpu/fpu_const.o \
../fpu/fpu_load_store.o \
../fpu/fpu_misc.o \
../fpu/fpu_tags.o \
../fpu/fpu_trans.o \
../fpu/fsincos.o \
../fpu/fyl2x.o \
../fpu/poly.o \
../fpu/softfloat-round-pack.o \
../fpu/softfloat-specialize.o \
../fpu/softfloat.o \
../fpu/softfloatx80.o 

CC_SRCS += \
../fpu/f2xm1.cc \
../fpu/ferr.cc \
../fpu/fpatan.cc \
../fpu/fprem.cc \
../fpu/fpu.cc \
../fpu/fpu_arith.cc \
../fpu/fpu_compare.cc \
../fpu/fpu_const.cc \
../fpu/fpu_load_store.cc \
../fpu/fpu_misc.cc \
../fpu/fpu_tags.cc \
../fpu/fpu_trans.cc \
../fpu/fsincos.cc \
../fpu/fyl2x.cc \
../fpu/poly.cc \
../fpu/softfloat-round-pack.cc \
../fpu/softfloat-specialize.cc \
../fpu/softfloat.cc \
../fpu/softfloatx80.cc 

OBJS += \
./fpu/f2xm1.o \
./fpu/ferr.o \
./fpu/fpatan.o \
./fpu/fprem.o \
./fpu/fpu.o \
./fpu/fpu_arith.o \
./fpu/fpu_compare.o \
./fpu/fpu_const.o \
./fpu/fpu_load_store.o \
./fpu/fpu_misc.o \
./fpu/fpu_tags.o \
./fpu/fpu_trans.o \
./fpu/fsincos.o \
./fpu/fyl2x.o \
./fpu/poly.o \
./fpu/softfloat-round-pack.o \
./fpu/softfloat-specialize.o \
./fpu/softfloat.o \
./fpu/softfloatx80.o 

CC_DEPS += \
./fpu/f2xm1.d \
./fpu/ferr.d \
./fpu/fpatan.d \
./fpu/fprem.d \
./fpu/fpu.d \
./fpu/fpu_arith.d \
./fpu/fpu_compare.d \
./fpu/fpu_const.d \
./fpu/fpu_load_store.d \
./fpu/fpu_misc.d \
./fpu/fpu_tags.d \
./fpu/fpu_trans.d \
./fpu/fsincos.d \
./fpu/fyl2x.d \
./fpu/poly.d \
./fpu/softfloat-round-pack.d \
./fpu/softfloat-specialize.d \
./fpu/softfloat.d \
./fpu/softfloatx80.d 


# Each subdirectory must supply rules for building sources it contributes
fpu/%.o: ../fpu/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


